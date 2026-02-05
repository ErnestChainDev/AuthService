from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import hashlib

from jose import jwt, JWTError
from passlib.context import CryptContext

MAX_BCRYPT_BYTES = 72

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def _password_bytes(password: str) -> bytes:
    if password is None:
        raise ValueError("Password is required")

    raw = password.encode("utf-8")

    if len(raw) > MAX_BCRYPT_BYTES:
        raise ValueError(
            "Password too long for bcrypt (max 72 bytes). "
            "Avoid emojis or shorten the password."
        )

    return raw


def hash_password(password: str) -> str:
    _password_bytes(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        _password_bytes(password)
        return pwd_context.verify(password, hashed)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    secret: str,
    algorithm: str,
    expires_minutes: int,
) -> str:
    if not secret:
        raise ValueError("JWT secret missing")

    payload = dict(data)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload["exp"] = expire

    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str, secret: str, algorithm: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[algorithm])
    except JWTError as e:
        raise ValueError("Invalid or expired token") from e


# -------------------------
# Reset Link Token Helpers (NOT OTP)
# -------------------------

def hash_reset_token(token: str) -> str:
    """
    Deterministic hash for reset-link tokens.
    Store this in DB instead of the raw token.
    """
    if not token:
        raise ValueError("Reset token is required")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_reset_token(token: str, token_hash: str) -> bool:
    """
    Compare a raw token to a stored hash.
    """
    try:
        return hash_reset_token(token) == token_hash
    except Exception:
        return False
