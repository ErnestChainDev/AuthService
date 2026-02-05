import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from authlib.jose import jwt as authlib_jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from shared.database import db_dependency
from shared.utils import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    hash_reset_token,      # ✅ NEW
    verify_reset_token,    # ✅ NEW
)

from .schemas import (
    RegisterIn,
    LoginIn,
    TokenOut,
    VerifyIn,
    VerifyOut,
    ForgotPasswordIn,
    ResetPasswordIn,
    GenericMsgOut,
)

from .crud import (
    get_or_create_user_google,     # expects email + google_sub
    get_user_by_email,
    create_user,
    upsert_password_reset_token,   # ✅ token-based
    get_password_reset_row,
    mark_reset_used,
    update_user_password,
)

from .email_utils import send_reset_link_email

load_dotenv()
router = APIRouter()

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.environ["JWT_ALGORITHM"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"])
RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", "15"))
FRONTEND_RESET_URL = os.getenv("FRONTEND_RESET_URL", "http://localhost:5173/reset-password")

# Google OAuth ENV
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "")
GOOGLE_OAUTH_SCOPES = os.getenv("GOOGLE_OAUTH_SCOPES", "openid email profile")

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"


def get_db_dep(SessionLocal):
    return db_dependency(SessionLocal)


def _require_google_env():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI.",
        )


def build_router(SessionLocal):
    get_db = get_db_dep(SessionLocal)

    # -------------------------
    # Register
    # -------------------------
    @router.post("/register", response_model=dict)
    def register(payload: RegisterIn, db: Session = Depends(get_db)):
        existing = get_user_by_email(db, payload.email)
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        u = create_user(db, payload.email, hash_password(payload.password))
        return {"id": u.id, "email": u.email}

    # -------------------------
    # Login
    # -------------------------
    @router.post("/login", response_model=TokenOut)
    def login(payload: LoginIn, db: Session = Depends(get_db)):
        u = get_user_by_email(db, payload.email)
        if not u or not verify_password(payload.password, u.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token(
            {"sub": str(u.id), "email": u.email},
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )
        return TokenOut(access_token=token)

    # -------------------------
    # Verify Token
    # -------------------------
    @router.post("/verify", response_model=VerifyOut)
    def verify(payload: VerifyIn):
        try:
            data = decode_token(payload.token, JWT_SECRET, JWT_ALGORITHM)
            return VerifyOut(sub=str(data.get("sub")), email=str(data.get("email")))
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    # =====================================================
    # Forgot Password (Send Reset Link) - TOKEN
    # =====================================================
    @router.post("/forgot-password", response_model=GenericMsgOut)
    def forgot_password(payload: ForgotPasswordIn, db: Session = Depends(get_db)):
        user = get_user_by_email(db, payload.email)

        safe_response = GenericMsgOut(
            detail="If the email exists, a password reset link has been sent."
        )

        if not user:
            return safe_response

        reset_token = secrets.token_urlsafe(32)

        # ✅ store HASH of reset token (deterministic)
        upsert_password_reset_token(
            db,
            user_id=user.id,
            email=user.email,
            token_hash=hash_reset_token(reset_token),
            expires_minutes=RESET_TOKEN_EXPIRE_MINUTES,
        )

        reset_link = f"{FRONTEND_RESET_URL}?email={user.email}&token={reset_token}"

        try:
            send_reset_link_email(user.email, reset_link)
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Failed to send reset email. Check SMTP configuration.",
            )

        return safe_response

    # =====================================================
    # Google OAuth (Login with Google)
    # =====================================================
    @router.get("/google/login")
    def google_login():
        _require_google_env()

        state = secrets.token_urlsafe(16)

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": GOOGLE_OAUTH_SCOPES,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }

        return RedirectResponse(url=f"{GOOGLE_AUTH_URL}?{urlencode(params)}")

    @router.get("/google/callback", response_model=TokenOut)
    async def google_callback(code: str, db: Session = Depends(get_db)):
        _require_google_env()

        async with httpx.AsyncClient(timeout=15) as client:
            token_res = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if token_res.status_code != 200:
            raise HTTPException(status_code=401, detail="Google token exchange failed.")

        token_data = token_res.json()
        id_token = token_data.get("id_token")
        if not id_token:
            raise HTTPException(status_code=401, detail="Google did not return id_token.")

        async with httpx.AsyncClient(timeout=15) as client:
            jwks = (await client.get(GOOGLE_JWKS_URL)).json()

        try:
            claims = authlib_jwt.decode(
                id_token,
                jwks,
                claims_options={
                    "iss": {"values": ["https://accounts.google.com", "accounts.google.com"]},
                    "aud": {"values": [GOOGLE_CLIENT_ID]},
                },
            )
            claims.validate()
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Google id_token.")

        email = claims.get("email")
        google_sub = claims.get("sub")

        if not email or not google_sub:
            raise HTTPException(status_code=401, detail="Missing email/sub from Google token.")

        u = get_or_create_user_google(db, email=email, google_sub=str(google_sub))

        token = create_access_token(
            {"sub": str(u.id), "email": u.email},
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )
        return TokenOut(access_token=token)

    # =====================================================
    # Reset Password (Token + Change Password) - TOKEN
    # =====================================================
    @router.post("/reset-password", response_model=GenericMsgOut)
    def reset_password(payload: ResetPasswordIn, db: Session = Depends(get_db)):
        user = get_user_by_email(db, payload.email)
        if not user:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        row = get_password_reset_row(db, user_id=user.id)
        if not row or row.used_at is not None:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        now = datetime.now(timezone.utc)
        if row.expires_at is None or row.expires_at.replace(tzinfo=timezone.utc) <= now:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        # ✅ compare using helper
        if not verify_reset_token(payload.token, row.token_hash):
            return GenericMsgOut(detail="Invalid or expired reset link.")

        update_user_password(
            db,
            user=user,
            new_password_hash=hash_password(payload.new_password),
        )

        mark_reset_used(db, row)

        return GenericMsgOut(detail="Password updated successfully.")

    return router
