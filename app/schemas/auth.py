"""
Authentication schemas for login, registration, and token management.
"""

import re
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.config import settings


class LoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecureP@ssw0rd!",
            }
        }


class RegisterRequest(BaseModel):
    """User registration request schema."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=settings.password_min_length,
        description=f"Password (min {settings.password_min_length} characters)",
    )
    confirm_password: str = Field(..., description="Password confirmation")
    full_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="User's full name",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        errors = []

        if len(v) < settings.password_min_length:
            errors.append(f"at least {settings.password_min_length} characters")
        if not re.search(r"[A-Z]", v):
            errors.append("at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            errors.append("at least one lowercase letter")
        if not re.search(r"\d", v):
            errors.append("at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            errors.append("at least one special character")

        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")

        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate that passwords match."""
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecureP@ssw0rd!",
                "confirm_password": "SecureP@ssw0rd!",
                "full_name": "John Doe",
            }
        }


class TokenResponse(BaseModel):
    """Token response schema for login/refresh."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: Literal["bearer"] = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 900,
            }
        }


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""

    refresh_token: str = Field(..., description="JWT refresh token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            }
        }


class PasswordResetRequest(BaseModel):
    """Password reset request (initiate) schema."""

    email: EmailStr = Field(..., description="Email address to send reset link")

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
            }
        }


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema."""

    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=settings.password_min_length,
        description="New password",
    )
    confirm_password: str = Field(..., description="Password confirmation")

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        errors = []

        if len(v) < settings.password_min_length:
            errors.append(f"at least {settings.password_min_length} characters")
        if not re.search(r"[A-Z]", v):
            errors.append("at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            errors.append("at least one lowercase letter")
        if not re.search(r"\d", v):
            errors.append("at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            errors.append("at least one special character")

        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")

        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate that passwords match."""
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class ChangePasswordRequest(BaseModel):
    """Change password request schema (for authenticated users)."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=settings.password_min_length,
        description="New password",
    )
    confirm_password: str = Field(..., description="Password confirmation")

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        errors = []

        if len(v) < settings.password_min_length:
            errors.append(f"at least {settings.password_min_length} characters")
        if not re.search(r"[A-Z]", v):
            errors.append("at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            errors.append("at least one lowercase letter")
        if not re.search(r"\d", v):
            errors.append("at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            errors.append("at least one special character")

        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")

        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        """Validate that passwords match."""
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v

    @field_validator("new_password")
    @classmethod
    def new_password_different(cls, v: str, info) -> str:
        """Validate that new password is different from current."""
        if "current_password" in info.data and v == info.data["current_password"]:
            raise ValueError("New password must be different from current password")
        return v


class GoogleAuthCallback(BaseModel):
    """Google OAuth callback data."""

    code: str = Field(..., description="Authorization code from Google")
    state: str | None = Field(default=None, description="State parameter for CSRF protection")
