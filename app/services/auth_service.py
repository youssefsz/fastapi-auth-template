"""
Authentication service for login, registration, and password operations.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    AccountDisabledException,
    AccountLockedException,
    InvalidCredentialsException,
    InvalidTokenException,
    UserNotFoundException,
)
from app.core.security import (
    generate_password_reset_token,
    hash_password,
    verify_password,
    verify_password_reset_token,
)
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.schemas.user import UserCreate
from app.services.token_service import TokenService
from app.services.user_service import UserService


class AuthService:
    """Service for authentication operations."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with database session."""
        self.db = db
        self.user_service = UserService(db)
        self.token_service = TokenService(db)

    async def register(
        self,
        register_data: RegisterRequest,
    ) -> tuple[User, str, str]:
        """
        Register a new user.

        Args:
            register_data: Registration data

        Returns:
            Tuple of (user, access_token, refresh_token)

        Raises:
            UserAlreadyExistsException: If email already exists
        """
        # Create user
        user_create = UserCreate(
            email=register_data.email,
            password=register_data.password,
            full_name=register_data.full_name,
        )
        user = await self.user_service.create(user_create)

        # Create tokens
        access_token, refresh_token = await self.token_service.create_token_pair(user)

        # Record login
        user.record_login()
        await self.db.flush()

        return user, access_token, refresh_token

    async def login(
        self,
        email: str,
        password: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[User, str, str]:
        """
        Authenticate a user with email and password.

        Args:
            email: User email
            password: User password
            user_agent: Client user agent
            ip_address: Client IP address

        Returns:
            Tuple of (user, access_token, refresh_token)

        Raises:
            InvalidCredentialsException: If credentials are invalid
            AccountLockedException: If account is locked
            AccountDisabledException: If account is disabled
        """
        # Get user
        user = await self.user_service.get_by_email(email)

        if not user:
            # Use constant-time comparison to prevent timing attacks
            # Hash a dummy password to keep timing consistent
            hash_password("dummy_password_for_timing")
            raise InvalidCredentialsException()

        # Check if account is locked
        if user.is_locked:
            raise AccountLockedException(
                lockout_minutes=settings.lockout_duration_minutes
            )

        # Check if account is active
        if not user.is_active:
            raise AccountDisabledException()

        # Check if user has a password (OAuth-only users cannot login with password)
        if not user.has_password:
            raise InvalidCredentialsException(
                "This account uses social login. Please sign in with Google."
            )

        # Verify password
        if not verify_password(password, user.hashed_password):  # type: ignore
            # Record failed attempt
            user.record_failed_login(
                max_attempts=settings.max_login_attempts,
                lockout_minutes=settings.lockout_duration_minutes,
            )
            await self.db.flush()
            raise InvalidCredentialsException()

        # Create tokens
        access_token, refresh_token = await self.token_service.create_token_pair(
            user,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Record successful login
        user.record_login()
        await self.db.flush()

        return user, access_token, refresh_token

    async def logout(
        self,
        refresh_token: str,
    ) -> bool:
        """
        Logout by revoking the refresh token.

        Args:
            refresh_token: The refresh token to revoke

        Returns:
            True if token was revoked
        """
        return await self.token_service.revoke_token(refresh_token)

    async def logout_all(
        self,
        user: User,
    ) -> int:
        """
        Logout from all devices by revoking all refresh tokens.

        Args:
            user: User to logout

        Returns:
            Number of sessions terminated
        """
        return await self.token_service.revoke_all_user_tokens(user.id)

    async def refresh_tokens(
        self,
        refresh_token: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[str, str, User]:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Current refresh token
            user_agent: Client user agent
            ip_address: Client IP address

        Returns:
            Tuple of (access_token, refresh_token, user)
        """
        return await self.token_service.refresh_tokens(
            refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
        )

    async def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> User:
        """
        Change user password.

        Args:
            user: User to change password for
            current_password: Current password for verification
            new_password: New password

        Returns:
            Updated user

        Raises:
            InvalidCredentialsException: If current password is wrong
        """
        if not user.has_password:
            raise InvalidCredentialsException(
                "Cannot change password for OAuth-only accounts"
            )

        if not verify_password(current_password, user.hashed_password):  # type: ignore
            raise InvalidCredentialsException("Current password is incorrect")

        # Update password
        user = await self.user_service.update_password(user, new_password)

        # Revoke all existing tokens (force re-login)
        await self.token_service.revoke_all_user_tokens(user.id)

        return user

    async def request_password_reset(
        self,
        email: str,
    ) -> str | None:
        """
        Generate password reset token for a user.

        Args:
            email: User email

        Returns:
            Reset token if user exists, None otherwise
            (We return None instead of raising to prevent enumeration)
        """
        user = await self.user_service.get_by_email(email)

        if not user:
            return None

        if not user.has_password:
            # OAuth-only users cannot reset password
            return None

        return generate_password_reset_token(email)

    async def reset_password(
        self,
        token: str,
        new_password: str,
    ) -> User:
        """
        Reset password using reset token.

        Args:
            token: Password reset token
            new_password: New password

        Returns:
            Updated user

        Raises:
            InvalidTokenException: If token is invalid
            UserNotFoundException: If user not found
        """
        email = verify_password_reset_token(token)
        if not email:
            raise InvalidTokenException("Invalid or expired reset token")

        user = await self.user_service.get_by_email(email)
        if not user:
            raise UserNotFoundException()

        # Update password
        user = await self.user_service.update_password(user, new_password)

        # Revoke all existing tokens
        await self.token_service.revoke_all_user_tokens(user.id)

        return user
