import os
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

import httpx
from authlib.jose import jwt as authlib_jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from shared.database import db_dependency
from shared.utils import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
    hash_reset_token,
    verify_reset_token,
)

from .schemas import (
    RegisterIn,
    LoginIn,
    VerifyIn,
    VerifyOut,
    ForgotPasswordIn,
    ResetPasswordIn,
    GenericMsgOut,
    AuthWithProfileOut,
)

from .crud import (
    get_or_create_user_google,
    get_user_by_email,
    create_user,
    upsert_password_reset_token,
    get_password_reset_row,
    mark_reset_used,
    update_user_password,
)

from .email_utils import send_reset_link_email

load_dotenv()
router = APIRouter()

STATE_COOKIE = "g_oauth_state"
RETURN_COOKIE = "g_oauth_return"
COOKIE_MAX_AGE = 10 * 60

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
FRONTEND_OAUTH_SUCCESS_URL = os.getenv("FRONTEND_OAUTH_SUCCESS_URL", "http://localhost:5173/oauth/success")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


def get_db_dep(SessionLocal):
    return db_dependency(SessionLocal)


def _require_google_env():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Set GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI.",
        )


def _safe_return_to(value: str | None) -> str:
    """
    Prevent open-redirect attacks.
    Only allow relative paths like '/dashboard' or '/profile-setup'.
    """
    if not value:
        return "/dashboard"
    value = value.strip()
    if not value.startswith("/"):
        return "/dashboard"
    if value.startswith("//"):
        return "/dashboard"
    return value

def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_router(SessionLocal):
    get_db = get_db_dep(SessionLocal)
    PROFILE_SERVICE_URL = os.getenv("PROFILE_SERVICE_URL", "").rstrip("/")
    JWT_SECRET = os.environ["JWT_SECRET"]
    JWT_ALGORITHM = os.environ["JWT_ALGORITHM"]
    SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
    
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET not configured")
    if not PROFILE_SERVICE_URL:
        raise RuntimeError("PROFILE_SERVICE_URL not configured")
    if not SERVICE_TOKEN:
        raise RuntimeError("SERVICE_TOKEN not configured")

    async def _bootstrap_profile(user_id: int, email: str, full_name: str = "") -> dict:
        url = f"{PROFILE_SERVICE_URL}/profile/internal/bootstrap"
        params = {"user_id": user_id, "email": email, "full_name": full_name}

        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(url, params=params, headers={"X-Service-Token": SERVICE_TOKEN})

        if res.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail=f"Profile bootstrap failed ({res.status_code}): {res.text}",
            )

        return res.json()

    # -------------------------
    # Register
    # -------------------------
    @router.post("/register", response_model=AuthWithProfileOut)
    async def register(payload: RegisterIn, db: Session = Depends(get_db)):
        existing = get_user_by_email(db, payload.email)
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        u = create_user(db, payload.email, hash_password(payload.password))

        # ✅ Create token
        token = create_access_token(
            {"sub": str(u.id), "email": u.email},
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        # ✅ Ensure profile exists now
        profile = await _bootstrap_profile(user_id=u.id, email=u.email)

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": u.id, "email": u.email},
            "profile": profile,
        }

    # -------------------------
    # Login
    # -------------------------
    @router.post("/login", response_model=AuthWithProfileOut)
    async def login(payload: LoginIn, db: Session = Depends(get_db)):
        u = get_user_by_email(db, payload.email)
        if not u or not verify_password(payload.password, u.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token(
            {"sub": str(u.id), "email": u.email},
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        # ✅ Ensure profile exists (idempotent)
        profile = await _bootstrap_profile(user_id=u.id, email=u.email)

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": u.id, "email": u.email},
            "profile": profile,
        }

    # -------------------------
    # Verify Token
    # -------------------------
    @router.post("/verify", response_model=VerifyOut)
    def verify(payload: VerifyIn):
        try:
            data = decode_token(payload.token, JWT_SECRET, JWT_ALGORITHM)

            sub = data.get("sub")
            email = data.get("email")

            if not sub:
                raise HTTPException(status_code=401, detail="Token missing sub")
            if not email:
                raise HTTPException(status_code=401, detail="Token missing email")

            return VerifyOut(sub=str(sub), email=str(email))

        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    # =====================================================
    # Forgot Password (Send Reset Link) - TOKEN
    # =====================================================
    @router.post("/forgot-password", response_model=GenericMsgOut)
    def forgot_password(payload: ForgotPasswordIn, db: Session = Depends(get_db)):
        user = get_user_by_email(db, payload.email)

        safe_response = GenericMsgOut(detail="If the email exists, a password reset link has been sent.")
        if not user:
            return safe_response

        reset_token = secrets.token_urlsafe(32)

        upsert_password_reset_token(
            db,
            user_id=user.id,
            email=user.email,
            token_hash=hash_reset_token(reset_token),
            expires_minutes=RESET_TOKEN_EXPIRE_MINUTES,
        )

        reset_link = f"{FRONTEND_RESET_URL}?email={quote(user.email)}&token={quote(reset_token)}"

        try:
            send_reset_link_email(user.email, reset_link)
        except Exception as e:
            print("SMTP ERROR:", repr(e))
            raise HTTPException(status_code=500,detail="Failed to send reset email. Check SMTP configuration.",)

        return safe_response
    

    @router.get("/debug/smtp-test")
    def smtp_test():
        send_reset_link_email("sorsulearnersportal@gmail.com", "http://localhost:5173/reset-password")
        return {"ok": True}

    # =====================================================
    # Google OAuth (Login with Google)
    # =====================================================
    @router.get("/google/login")
    def google_login(request: Request, return_to: str | None = None):
        _require_google_env()

        state = secrets.token_urlsafe(24)

        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": GOOGLE_OAUTH_SCOPES,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }

        redirect = RedirectResponse(
            url=f"{GOOGLE_AUTH_URL}?{urlencode(params)}",
            status_code=302,
        )

        redirect.set_cookie(
            key=STATE_COOKIE,
            value=state,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=COOKIE_SECURE,
        )

        # ✅ always store a safe return_to
        safe_return = _safe_return_to(return_to)
        redirect.set_cookie(
            key=RETURN_COOKIE,
            value=safe_return,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=COOKIE_SECURE,
        )

        return redirect

    @router.get("/google/callback")
    async def google_callback_redirect(
        request: Request,
        code: str,
        state: str | None = None,
        db: Session = Depends(get_db),  # ✅ typed correctly
    ):
        _require_google_env()

        expected_state = request.cookies.get(STATE_COOKIE)
        if not expected_state or not state or state != expected_state:
            raise HTTPException(status_code=400, detail="Invalid OAuth state.")

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
        full_name = (claims.get("name") or "").strip()
        if not email or not google_sub:
            raise HTTPException(status_code=401, detail="Missing email/sub from Google token.")

        # ✅ FIX: this line was broken in your code
        user = get_or_create_user_google(db, email=str(email), google_sub=str(google_sub))

        # ✅ Ensure profile exists and store name if available
        await _bootstrap_profile(user_id=user.id, email=user.email, full_name=full_name)

        access_token = create_access_token(
            {"sub": str(user.id), "email": user.email},
            secret=JWT_SECRET,
            algorithm=JWT_ALGORITHM,
            expires_minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        return_to_cookie = request.cookies.get(RETURN_COOKIE)
        return_to = _safe_return_to(return_to_cookie)

        # ✅ safe URL params
        redirect_url = (
            f"{FRONTEND_OAUTH_SUCCESS_URL}"
            f"?token={quote(access_token)}"
            f"&return_to={quote(return_to)}"
        )

        redirect = RedirectResponse(url=redirect_url, status_code=302)

        redirect.delete_cookie(STATE_COOKIE)
        redirect.delete_cookie(RETURN_COOKIE)

        return redirect

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

        if not row.expires_at:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        now = datetime.now(timezone.utc)
        if _as_utc(row.expires_at) <= now:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        if not row.token_hash:
            return GenericMsgOut(detail="Invalid or expired reset link.")

        if not verify_reset_token(payload.token, row.token_hash):
            return GenericMsgOut(detail="Invalid or expired reset link.")

        update_user_password(db, user=user, new_password_hash=hash_password(payload.new_password))
        mark_reset_used(db, row)

        return GenericMsgOut(detail="Password updated successfully.")

    return router