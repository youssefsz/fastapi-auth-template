"""
Google OAuth service for authentication with Google.
"""

import json
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import OAuthException
from app.models.oauth import OAuthAccount
from app.models.user import User
from app.services.token_service import TokenService
from app.services.user_service import UserService

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


class GoogleOAuthService:
    """Service for Google OAuth authentication."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with database session."""
        self.db = db
        self.user_service = UserService(db)
        self.token_service = TokenService(db)

    def get_authorization_url(self, redirect_uri: str, state: str | None = None) -> str:
        """
        Get Google OAuth authorization URL.

        Args:
            redirect_uri: Redirect URI to use
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL to redirect user to
        """
        if not settings.google_oauth_enabled:
            raise OAuthException("Google OAuth is not configured", provider="google")

        client = AsyncOAuth2Client(
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            redirect_uri=redirect_uri,
        )

        url, _ = client.create_authorization_url(
            GOOGLE_AUTH_URL,
            scope="openid email profile",
            state=state,
            access_type="offline",  # Get refresh token
            prompt="consent",  # Force consent to get refresh token
        )

        return url

    async def authenticate(
        self,
        code: str,
        redirect_uri: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[User, str, str, bool]:
        """
        Authenticate user with Google OAuth code.

        Args:
            code: Authorization code from Google
            redirect_uri: Redirect URI used for authorization
            user_agent: Client user agent
            ip_address: Client IP address

        Returns:
            Tuple of (user, access_token, refresh_token, is_new_user)

        Raises:
            OAuthException: If authentication fails
        """
        if not settings.google_oauth_enabled:
            raise OAuthException("Google OAuth is not configured", provider="google")

        try:
            # Exchange code for tokens
            async with httpx.AsyncClient() as client:
                token_response = await client.post(
                    GOOGLE_TOKEN_URL,
                    data={
                        "client_id": settings.google_client_id,
                        "client_secret": settings.google_client_secret,
                        "code": code,
                        "grant_type": "authorization_code",
                        "redirect_uri": redirect_uri,
                    },
                )

                if token_response.status_code != 200:
                    raise OAuthException(
                        f"Failed to exchange code for tokens: {token_response.text}",
                        provider="google",
                    )

                token_data = token_response.json()

                # Get user info
                userinfo_response = await client.get(
                    GOOGLE_USERINFO_URL,
                    headers={
                        "Authorization": f"Bearer {token_data['access_token']}"
                    },
                )

                if userinfo_response.status_code != 200:
                    raise OAuthException(
                        "Failed to get user info from Google",
                        provider="google",
                    )

                userinfo = userinfo_response.json()

        except httpx.RequestError as e:
            raise OAuthException(f"Network error: {str(e)}", provider="google")

        # Extract user data
        google_id = userinfo.get("sub")
        email = userinfo.get("email")
        name = userinfo.get("name")
        picture = userinfo.get("picture")
        email_verified = userinfo.get("email_verified", False)

        if not google_id or not email:
            raise OAuthException("Invalid user data from Google", provider="google")

        if not email_verified:
            raise OAuthException("Email not verified by Google", provider="google")

        # Find or create user
        user, is_new_user = await self._find_or_create_user(
            google_id=google_id,
            email=email,
            name=name,
            picture=picture,
            token_data=token_data,
        )

        # Create tokens
        access_token, refresh_token = await self.token_service.create_token_pair(
            user,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Record login
        user.record_login()
        await self.db.flush()

        return user, access_token, refresh_token, is_new_user

    async def _find_or_create_user(
        self,
        google_id: str,
        email: str,
        name: str | None,
        picture: str | None,
        token_data: dict[str, Any],
    ) -> tuple[User, bool]:
        """
        Find existing user or create new one from Google data.

        Args:
            google_id: Google user ID
            email: User email
            name: User's name
            picture: User's profile picture URL
            token_data: OAuth token data

        Returns:
            Tuple of (user, is_new_user)
        """
        # Check for existing OAuth account
        result = await self.db.execute(
            select(OAuthAccount).where(
                and_(
                    OAuthAccount.provider == "google",
                    OAuthAccount.provider_user_id == google_id,
                )
            )
        )
        oauth_account = result.scalar_one_or_none()

        if oauth_account:
            # Existing OAuth account - update tokens and return user
            oauth_account.access_token = token_data.get("access_token")
            oauth_account.refresh_token = token_data.get("refresh_token")
            oauth_account.raw_data = json.dumps(token_data)

            # Calculate token expiration
            if "expires_in" in token_data:
                from datetime import datetime, timedelta, timezone

                oauth_account.token_expires_at = datetime.now(timezone.utc) + timedelta(
                    seconds=token_data["expires_in"]
                )

            await self.db.flush()

            # Load user relationship
            result = await self.db.execute(
                select(User).where(User.id == oauth_account.user_id)
            )
            user = result.scalar_one()

            return user, False

        # Check if user exists with this email
        user = await self.user_service.get_by_email(email)
        is_new_user = False

        if not user:
            # Create new user
            user = await self.user_service.create_oauth_user(
                email=email,
                full_name=name,
                avatar_url=picture,
            )
            is_new_user = True
        else:
            # Link OAuth to existing account (account linking)
            # Update profile if fields are empty
            if not user.full_name and name:
                user.full_name = name
            if not user.avatar_url and picture:
                user.avatar_url = picture

        # Create OAuth account link
        oauth_account = OAuthAccount(
            user_id=user.id,
            provider="google",
            provider_user_id=google_id,
            provider_email=email,
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            raw_data=json.dumps(token_data),
        )

        if "expires_in" in token_data:
            from datetime import datetime, timedelta, timezone

            oauth_account.token_expires_at = datetime.now(timezone.utc) + timedelta(
                seconds=token_data["expires_in"]
            )

        self.db.add(oauth_account)
        await self.db.flush()

        return user, is_new_user

    async def unlink_account(self, user: User) -> bool:
        """
        Unlink Google account from user.

        Args:
            user: User to unlink

        Returns:
            True if account was unlinked

        Raises:
            OAuthException: If this is the only login method
        """
        # Check if user has a password (alternative login method)
        if not user.has_password:
            raise OAuthException(
                "Cannot unlink Google account - it's your only login method. "
                "Please set a password first.",
                provider="google",
            )

        # Find and delete OAuth account
        result = await self.db.execute(
            select(OAuthAccount).where(
                and_(
                    OAuthAccount.user_id == user.id,
                    OAuthAccount.provider == "google",
                )
            )
        )
        oauth_account = result.scalar_one_or_none()

        if not oauth_account:
            return False

        await self.db.delete(oauth_account)
        await self.db.flush()

        return True
