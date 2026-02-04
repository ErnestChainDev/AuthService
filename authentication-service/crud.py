from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from .models import UserAuth, PasswordResetOTP


# -------------------------
# Users
# -------------------------

def get_user_by_email(db: Session, email: str):
    return db.query(UserAuth).filter(UserAuth.email == email).first()

def create_user(db: Session, email: str, password_hash: str):
    u = UserAuth(email=email, password_hash=password_hash)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

def update_user_password(db: Session, user: UserAuth, new_password_hash: str) -> UserAuth:
    user.password_hash = new_password_hash
    db.commit()
    db.refresh(user)
    return user


# -------------------------
# Password Reset OTP
# -------------------------

def get_password_reset_row(db: Session, user_id: int) -> PasswordResetOTP | None:
    return db.query(PasswordResetOTP).filter(PasswordResetOTP.user_id == user_id).first()

def upsert_password_reset_otp(
    db: Session,
    *,
    user_id: int,
    email: str,
    otp_hash: str,
    expires_minutes: int = 10,
) -> PasswordResetOTP:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=expires_minutes)

    row = get_password_reset_row(db, user_id)
    if not row:
        row = PasswordResetOTP(
            user_id=user_id,
            email=email,
            otp_hash=otp_hash,
            expires_at=expires_at,
            used_at=None,
        )
        db.add(row)
    else:
        row.email = email
        row.otp_hash = otp_hash
        row.expires_at = expires_at
        row.used_at = None  # reset usage if re-requesting OTP

    db.commit()
    db.refresh(row)
    return row

def mark_reset_used(db: Session, row: PasswordResetOTP) -> None:
    row.used_at = datetime.now(timezone.utc)
    db.commit()

def is_reset_otp_valid(db: Session, user_id: int) -> bool:
    """
    Returns True if there's an unused, unexpired OTP row for this user.
    (Useful if you want to prevent spamming OTP requests.)
    """
    row = get_password_reset_row(db, user_id)
    if not row:
        return False
    if row.used_at is not None:
        return False
    return row.expires_at >= datetime.now(timezone.utc)

def can_request_new_otp(db: Session, user_id: int, cooldown_seconds: int = 60) -> bool:
    """
    Simple cooldown: allow new OTP request only if the last OTP was created more than cooldown_seconds ago.
    """
    row = get_password_reset_row(db, user_id)
    if not row:
        return True
    # if created_at missing for some reason, allow
    try:
        return (datetime.now(timezone.utc) - row.created_at).total_seconds() >= cooldown_seconds
    except Exception:
        return True
