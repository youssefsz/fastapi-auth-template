"""
User service for user-related database operations.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import UserAlreadyExistsException, UserNotFoundException
from app.core.security import hash_password
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


class UserService:
    """Service for user database operations."""

    def __init__(self, db: AsyncSession) -> None:
        """Initialize with database session."""
        self.db = db

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """
        Get a user by ID.

        Args:
            user_id: User UUID

        Returns:
            User if found, None otherwise
        """
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """
        Get a user by email.

        Args:
            email: User email address

        Returns:
            User if found, None otherwise
        """
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        user_data: UserCreate,
        is_verified: bool = False,
    ) -> User:
        """
        Create a new user.

        Args:
            user_data: User creation data
            is_verified: Whether to mark email as verified

        Returns:
            Created user

        Raises:
            UserAlreadyExistsException: If email already exists
        """
        # Check for existing user
        existing = await self.get_by_email(user_data.email)
        if existing:
            raise UserAlreadyExistsException()

        # Create user
        user = User(
            email=user_data.email.lower(),
            hashed_password=hash_password(user_data.password),
            full_name=user_data.full_name,
            is_verified=is_verified,
            password_changed_at=datetime.now(timezone.utc),
        )

        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)

        return user

    async def create_oauth_user(
        self,
        email: str,
        full_name: str | None = None,
        avatar_url: str | None = None,
    ) -> User:
        """
        Create a new user from OAuth provider.

        Args:
            email: User email from OAuth
            full_name: User's full name
            avatar_url: User's avatar URL

        Returns:
            Created user
        """
        user = User(
            email=email.lower(),
            full_name=full_name,
            avatar_url=avatar_url,
            is_verified=True,  # OAuth emails are verified by the provider
            hashed_password=None,  # No password for OAuth-only users
        )

        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)

        return user

    async def update(
        self,
        user: User,
        user_data: UserUpdate,
    ) -> User:
        """
        Update a user.

        Args:
            user: User to update
            user_data: Update data

        Returns:
            Updated user
        """
        update_data = user_data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            setattr(user, field, value)

        await self.db.flush()
        await self.db.refresh(user)

        return user

    async def update_password(
        self,
        user: User,
        new_password: str,
    ) -> User:
        """
        Update a user's password.

        Args:
            user: User to update
            new_password: New plain text password

        Returns:
            Updated user
        """
        user.hashed_password = hash_password(new_password)
        user.password_changed_at = datetime.now(timezone.utc)

        await self.db.flush()
        await self.db.refresh(user)

        return user

    async def delete(self, user: User) -> None:
        """
        Delete a user.

        Args:
            user: User to delete
        """
        await self.db.delete(user)
        await self.db.flush()

    async def activate(self, user: User) -> User:
        """
        Activate a user account.

        Args:
            user: User to activate

        Returns:
            Updated user
        """
        user.is_active = True
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def deactivate(self, user: User) -> User:
        """
        Deactivate a user account.

        Args:
            user: User to deactivate

        Returns:
            Updated user
        """
        user.is_active = False
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def verify_email(self, user: User) -> User:
        """
        Mark user email as verified.

        Args:
            user: User to verify

        Returns:
            Updated user
        """
        user.is_verified = True
        await self.db.flush()
        await self.db.refresh(user)
        return user
