"""
Refresh token model for secure token management.

Stores refresh tokens in the database for revocation and tracking.
"""

import uuid
from datetime import datetime, timezone as tz
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


class RefreshToken(Base, TimestampMixin):
    """Refresh token model for JWT refresh token management."""

    __tablename__ = "refresh_tokens"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )

    # Token identifier (the jti claim from JWT)
    token_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    # Foreign key to user
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Token metadata
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Client info for audit
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv6 length

    # Token family for rotation detection
    family_id: Mapped[str | None] = mapped_column(
        String(64),
        index=True,
        nullable=True,
    )
    replaced_by: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

    def __repr__(self) -> str:
        return f"<RefreshToken {self.token_id[:8]}...>"

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.now(tz.utc) >= self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and not revoked)."""
        return not self.is_expired and not self.is_revoked

    def revoke(self) -> None:
        """Revoke this token."""
        self.is_revoked = True
        self.revoked_at = datetime.now(tz.utc)
