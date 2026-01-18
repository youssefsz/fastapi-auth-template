"""
Token service for refresh token management.
"""

import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import InvalidTokenException, TokenRevokedException
from app.core.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.models.refresh_token import RefreshToken
from app.models.user import User


class TokenService:
    """Service for token management and refresh token persistence."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with database session."""
        self.db = db

    async def create_token_pair(
        self,
        user: User,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[str, str]:
        """
        Create access and refresh token pair.

        Args:
            user: User to create tokens for
            user_agent: Client user agent
            ip_address: Client IP address

        Returns:
            Tuple of (access_token, refresh_token)
        """
        # Create access token
        access_token = create_access_token(subject=str(user.id))

        # Create refresh token
        refresh_token_str, token_id, expires_at = create_refresh_token(
            subject=str(user.id)
        )

        # Generate family ID for token rotation tracking
        family_id = secrets.token_urlsafe(32)

        # Store refresh token in database
        refresh_token = RefreshToken(
            token_id=token_id,
            user_id=user.id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
            family_id=family_id,
        )

        self.db.add(refresh_token)
        await self.db.flush()

        return access_token, refresh_token_str

    async def refresh_tokens(
        self,
        refresh_token_str: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[str, str, User]:
        """
        Refresh tokens using a valid refresh token.

        Implements token rotation: the old refresh token is revoked
        and a new pair is issued.

        Args:
            refresh_token_str: The refresh token JWT
            user_agent: Client user agent
            ip_address: Client IP address

        Returns:
            Tuple of (access_token, refresh_token, user)

        Raises:
            InvalidTokenException: If token is invalid or expired
            TokenRevokedException: If token has been revoked
        """
        # Decode and validate token
        payload = decode_token(refresh_token_str)
        if not payload:
            raise InvalidTokenException()

        # Verify token type
        if payload.get("type") != TokenType.REFRESH:
            raise InvalidTokenException("Invalid token type")

        token_id = payload.get("jti")
        user_id = payload.get("sub")

        if not token_id or not user_id:
            raise InvalidTokenException()

        # Get token from database
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token_id == token_id)
        )
        stored_token = result.scalar_one_or_none()

        if not stored_token:
            raise InvalidTokenException()

        # Check if token is revoked (possible replay attack)
        if stored_token.is_revoked:
            # Token reuse detected! Revoke entire family
            await self._revoke_token_family(stored_token.family_id)
            raise TokenRevokedException("Token has been revoked. All sessions invalidated for security.")

        # Check if token is expired
        if stored_token.is_expired:
            raise InvalidTokenException("Refresh token has expired")

        # Revoke old token (rotation)
        stored_token.revoke()

        # Get user
        from app.models.user import User

        result = await self.db.execute(
            select(User).where(User.id == uuid.UUID(user_id))
        )
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise InvalidTokenException("User not found or inactive")

        # Create new access token
        access_token = create_access_token(subject=str(user.id))

        # Create new refresh token (same family for rotation tracking)
        new_refresh_str, new_token_id, expires_at = create_refresh_token(
            subject=str(user.id)
        )

        # Link old token to new one
        stored_token.replaced_by = new_token_id

        # Store new refresh token
        new_refresh_token = RefreshToken(
            token_id=new_token_id,
            user_id=user.id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
            family_id=stored_token.family_id,  # Same family
        )

        self.db.add(new_refresh_token)
        await self.db.flush()

        return access_token, new_refresh_str, user

    async def revoke_token(self, refresh_token_str: str) -> bool:
        """
        Revoke a specific refresh token.

        Args:
            refresh_token_str: The refresh token JWT

        Returns:
            True if token was revoked, False if not found
        """
        payload = decode_token(refresh_token_str)
        if not payload:
            return False

        token_id = payload.get("jti")
        if not token_id:
            return False

        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.token_id == token_id)
        )
        token = result.scalar_one_or_none()

        if not token:
            return False

        token.revoke()
        await self.db.flush()

        return True

    async def revoke_all_user_tokens(self, user_id: uuid.UUID) -> int:
        """
        Revoke all refresh tokens for a user.

        Args:
            user_id: User ID

        Returns:
            Number of tokens revoked
        """
        result = await self.db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.user_id == user_id,
                    RefreshToken.is_revoked == False,  # noqa: E712
                )
            )
        )
        tokens = result.scalars().all()

        count = 0
        for token in tokens:
            token.revoke()
            count += 1

        await self.db.flush()
        return count

    async def _revoke_token_family(self, family_id: str | None) -> None:
        """
        Revoke all tokens in a family (for replay attack detection).

        Args:
            family_id: Token family ID
        """
        if not family_id:
            return

        result = await self.db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.family_id == family_id,
                    RefreshToken.is_revoked == False,  # noqa: E712
                )
            )
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.revoke()

        await self.db.flush()

    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from database.

        Returns:
            Number of tokens deleted
        """
        result = await self.db.execute(
            delete(RefreshToken).where(
                RefreshToken.expires_at < datetime.now(timezone.utc)
            )
        )
        await self.db.flush()
        return result.rowcount or 0

    async def get_user_active_sessions(
        self,
        user_id: uuid.UUID,
    ) -> list[RefreshToken]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active refresh tokens
        """
        result = await self.db.execute(
            select(RefreshToken).where(
                and_(
                    RefreshToken.user_id == user_id,
                    RefreshToken.is_revoked == False,  # noqa: E712
                    RefreshToken.expires_at > datetime.now(timezone.utc),
                )
            )
        )
        return list(result.scalars().all())
