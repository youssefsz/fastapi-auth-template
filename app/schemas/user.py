"""
User schemas for user data transfer objects.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user schema with common fields."""

    email: EmailStr = Field(..., description="User email address")
    full_name: str | None = Field(default=None, max_length=255, description="User's full name")


class UserCreate(UserBase):
    """Schema for creating a user."""

    password: str = Field(..., min_length=8, description="User password")


class UserUpdate(BaseModel):
    """Schema for updating a user."""

    full_name: str | None = Field(default=None, max_length=255, description="User's full name")
    avatar_url: str | None = Field(default=None, description="User's avatar URL")


class UserResponse(BaseModel):
    """User response schema (public data)."""

    id: uuid.UUID = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email address")
    full_name: str | None = Field(default=None, description="User's full name")
    avatar_url: str | None = Field(default=None, description="User's avatar URL")
    is_active: bool = Field(..., description="Whether the user account is active")
    is_verified: bool = Field(..., description="Whether the email is verified")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login: datetime | None = Field(default=None, description="Last login timestamp")
    has_password: bool = Field(..., description="Whether the user has a password set")
    oauth_providers: list[str] = Field(
        default_factory=list, description="Connected OAuth providers"
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "full_name": "John Doe",
                "avatar_url": "https://example.com/avatar.jpg",
                "is_active": True,
                "is_verified": True,
                "created_at": "2024-01-15T10:30:00Z",
                "last_login": "2024-01-15T12:00:00Z",
                "has_password": True,
                "oauth_providers": ["google"],
            }
        }


class UserInDB(UserResponse):
    """User schema with internal data (not exposed via API)."""

    hashed_password: str | None = Field(default=None, description="Hashed password")
    is_superuser: bool = Field(default=False, description="Whether the user is a superuser")
    failed_login_attempts: int = Field(default=0, description="Failed login attempts")
    locked_until: datetime | None = Field(default=None, description="Account lock expiration")


class UserWithTokens(BaseModel):
    """User response with authentication tokens."""

    user: UserResponse = Field(..., description="User data")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "email": "user@example.com",
                    "full_name": "John Doe",
                    "avatar_url": None,
                    "is_active": True,
                    "is_verified": True,
                    "created_at": "2024-01-15T10:30:00Z",
                    "last_login": "2024-01-15T12:00:00Z",
                    "has_password": True,
                    "oauth_providers": [],
                },
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 900,
            }
        }
