"""
Custom exceptions for the authentication system.

All exceptions inherit from a base exception for consistency.
"""

from typing import Any


class AuthException(Exception):
    """Base exception for authentication errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.error_code = error_code or "AUTH_ERROR"
        self.details = details or {}
        super().__init__(message)


class InvalidCredentialsException(AuthException):
    """Raised when login credentials are invalid."""

    def __init__(self, message: str = "Invalid email or password") -> None:
        super().__init__(message, error_code="INVALID_CREDENTIALS")


class UserNotFoundException(AuthException):
    """Raised when a user is not found."""

    def __init__(self, message: str = "User not found") -> None:
        super().__init__(message, error_code="USER_NOT_FOUND")


class UserAlreadyExistsException(AuthException):
    """Raised when attempting to create a user that already exists."""

    def __init__(self, message: str = "A user with this email already exists") -> None:
        super().__init__(message, error_code="USER_EXISTS")


class InvalidTokenException(AuthException):
    """Raised when a token is invalid or expired."""

    def __init__(self, message: str = "Invalid or expired token") -> None:
        super().__init__(message, error_code="INVALID_TOKEN")


class TokenRevokedException(AuthException):
    """Raised when a token has been revoked."""

    def __init__(self, message: str = "Token has been revoked") -> None:
        super().__init__(message, error_code="TOKEN_REVOKED")


class AccountLockedException(AuthException):
    """Raised when an account is locked due to too many failed attempts."""

    def __init__(
        self,
        message: str = "Account is temporarily locked due to too many failed login attempts",
        lockout_minutes: int = 15,
    ) -> None:
        super().__init__(
            message,
            error_code="ACCOUNT_LOCKED",
            details={"lockout_minutes": lockout_minutes},
        )


class AccountDisabledException(AuthException):
    """Raised when an account has been disabled."""

    def __init__(self, message: str = "Account has been disabled") -> None:
        super().__init__(message, error_code="ACCOUNT_DISABLED")


class OAuthException(AuthException):
    """Raised when OAuth authentication fails."""

    def __init__(
        self,
        message: str = "OAuth authentication failed",
        provider: str = "unknown",
    ) -> None:
        super().__init__(
            message,
            error_code="OAUTH_ERROR",
            details={"provider": provider},
        )


class PasswordValidationException(AuthException):
    """Raised when password does not meet requirements."""

    def __init__(
        self,
        message: str = "Password does not meet requirements",
        requirements: list[str] | None = None,
    ) -> None:
        super().__init__(
            message,
            error_code="INVALID_PASSWORD",
            details={"requirements": requirements or []},
        )


class RateLimitExceededException(AuthException):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Too many requests. Please try again later.",
        retry_after: int = 60,
    ) -> None:
        super().__init__(
            message,
            error_code="RATE_LIMIT_EXCEEDED",
            details={"retry_after_seconds": retry_after},
        )
