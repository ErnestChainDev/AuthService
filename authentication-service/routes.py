import os
import random
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from shared.database import db_dependency
from shared.utils import (hash_password,verify_password,create_access_token,decode_token,hash_otp,verify_otp,)

from .schemas import (RegisterIn,LoginIn,TokenOut,VerifyIn,VerifyOut,ForgotPasswordIn,ResetPasswordIn,GenericMsgOut,)
from .crud import (get_user_by_email,create_user,upsert_password_reset_otp,get_password_reset_row,mark_reset_used,update_user_password,)
from .email_utils import send_otp_email


load_dotenv()
router = APIRouter()

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.environ["JWT_ALGORITHM"]
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"])
RESET_OTP_EXPIRE_MINUTES = int(os.getenv("RESET_OTP_EXPIRE_MINUTES", "10"))


def get_db_dep(SessionLocal):
    return db_dependency(SessionLocal)


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
    # Forgot Password (Send OTP)
    # =====================================================
    @router.post("/forgot-password", response_model=GenericMsgOut)
    def forgot_password(payload: ForgotPasswordIn, db: Session = Depends(get_db)):
        """
        Sends a 6-digit OTP to the user's email.
        IMPORTANT: Response is always generic to avoid email enumeration.
        """
        user = get_user_by_email(db, payload.email)

        # Always return same message (security best practice)
        safe_response = GenericMsgOut(
            detail="If the email exists, an OTP has been sent."
        )

        if not user:
            return safe_response

        # Generate 6-digit OTP
        otp = f"{random.randint(0, 999999):06d}"

        # Store hashed OTP with expiry
        upsert_password_reset_otp(
            db,
            user_id=user.id,
            email=user.email,
            otp_hash=hash_otp(otp),
            expires_minutes=RESET_OTP_EXPIRE_MINUTES,
        )

        # Send email
        try:
            send_otp_email(user.email, otp)
        except Exception as e:
            # Log e in Railway logs; do not leak details to client
            raise HTTPException(
                status_code=500,
                detail="Failed to send OTP email. Check SMTP configuration.",
            )

        return safe_response

    # =====================================================
    # Reset Password (Verify OTP + Change Password)
    # =====================================================
    @router.post("/reset-password", response_model=GenericMsgOut)
    def reset_password(payload: ResetPasswordIn, db: Session = Depends(get_db)):
        user = get_user_by_email(db, payload.email)
        if not user:
            return GenericMsgOut(detail="Invalid OTP or expired OTP.")

        row = get_password_reset_row(db, user_id=user.id)
        if not row or row.used_at is not None:
            return GenericMsgOut(detail="Invalid OTP or expired OTP.")

        now = datetime.now(timezone.utc)
        if row.expires_at is None or row.expires_at.replace(tzinfo=timezone.utc) <= now:
            return GenericMsgOut(detail="Invalid OTP or expired OTP.")

        if not verify_otp(payload.otp, row.otp_hash):
            return GenericMsgOut(detail="Invalid OTP or expired OTP.")

        # Update password
        update_user_password(
            db,
            user=user,
            new_password_hash=hash_password(payload.new_password),
        )

        # Mark OTP as used
        mark_reset_used(db, row)

        return GenericMsgOut(detail="Password updated successfully.")

    return router
