from datetime import datetime, timedelta, timezone
import secrets
from sqlalchemy.orm import Session

from shared.utils import hash_password
from .models import UserAuth, PasswordResetToken


# -------------------------
# Users
# -------------------------

def get_user_by_email(db: Session, email: str) -> UserAuth | None:
    return db.query(UserAuth).filter(UserAuth.email == email).first()


def get_user_by_google_sub(db: Session, google_sub: str) -> UserAuth | None:
    return db.query(UserAuth).filter(UserAuth.google_sub == google_sub).first()


def create_user(db: Session, email: str, password_hash: str) -> UserAuth:
    """
    Creates a LOCAL user by default (auth_provider='local').
    """
    u = UserAuth(
        email=email,
        password_hash=password_hash,
        auth_provider="local",
        google_sub=None,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def update_user_password(db: Session, user: UserAuth, new_password_hash: str) -> UserAuth:
    user.password_hash = new_password_hash
    db.commit()
    db.refresh(user)
    return user


def get_or_create_user_google(db: Session, *, email: str, google_sub: str) -> UserAuth:
    """
    Google sign-in:
    1) Prefer google_sub match (stable unique id)
    2) Else link by email (policy: allow linking)
    3) Else create new user marked as google
    """
    u = get_user_by_google_sub(db, google_sub)
    if u:
        if u.email != email:
            u.email = email
            db.commit()
            db.refresh(u)
        return u

    u = get_user_by_email(db, email)
    if u:
        u.google_sub = google_sub
        u.auth_provider = "google"
        db.commit()
        db.refresh(u)
        return u

    random_pw = secrets.token_urlsafe(32)
    u = UserAuth(
        email=email,
        password_hash=hash_password(random_pw),
        auth_provider="google",
        google_sub=google_sub,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


# -------------------------
# Password Reset LINK (Token)
# -------------------------

def get_password_reset_row(db: Session, user_id: int) -> PasswordResetToken | None:
    return (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == user_id)
        .first()
    )


def upsert_password_reset_token(
    db: Session,
    *,
    user_id: int,
    email: str,
    token_hash: str,
    expires_minutes: int = 10,
) -> PasswordResetToken:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=expires_minutes)

    row = get_password_reset_row(db, user_id)
    if not row:
        row = PasswordResetToken(
            user_id=user_id,
            email=email,
            token_hash=token_hash,
            expires_at=expires_at,
            used_at=None,
        )
        db.add(row)
    else:
        row.email = email
        row.token_hash = token_hash
        row.expires_at = expires_at
        row.used_at = None

    db.commit()
    db.refresh(row)
    return row


def mark_reset_used(db: Session, row: PasswordResetToken) -> None:
    row.used_at = datetime.now(timezone.utc)
    db.commit()


def is_reset_token_valid(db: Session, user_id: int) -> bool:
    row = get_password_reset_row(db, user_id)
    if not row:
        return False
    if row.used_at is not None:
        return False

    now = datetime.now(timezone.utc)
    exp = row.expires_at
    # guard in case DB returns naive datetime
    if exp is None:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    return exp >= now


def can_request_new_reset(db: Session, user_id: int, cooldown_seconds: int = 60) -> bool:
    row = get_password_reset_row(db, user_id)
    if not row:
        return True

    created = row.created_at
    if created is None:
        return True
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    return (datetime.now(timezone.utc) - created).total_seconds() >= cooldown_seconds