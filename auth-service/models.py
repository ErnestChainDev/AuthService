from datetime import datetime
from sqlalchemy import String, Integer, DateTime, func, UniqueConstraint, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from shared.database import Base


# -------------------------
# Main Auth User Table
# -------------------------

class UserAuth(Base):
    __tablename__ = "user_auth"
    __table_args__ = (UniqueConstraint("email", name="uq_user_auth_email"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # how the account was created: local | google
    auth_provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default="local",
    )

    # Google stable unique user id (sub)
    google_sub: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        unique=True,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )


# -------------------------
# Password Reset Token Table (RESET LINK, NOT OTP)
# -------------------------

class PasswordResetToken(Base):
    __tablename__ = "password_reset_token"
    __table_args__ = (
        # only one active reset token per user
        UniqueConstraint("user_id", name="uq_password_reset_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("user_auth.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # HASH of the reset token sent via email
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # set when the token is used (one-time)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
