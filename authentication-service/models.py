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
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


# -------------------------
# Password Reset OTP Table
# -------------------------

class PasswordResetOTP(Base):
    __tablename__ = "password_reset_otp"
    __table_args__ = (
        # Only one active OTP row per user
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

    otp_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
