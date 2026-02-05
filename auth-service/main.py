import os
from dotenv import load_dotenv
from fastapi import FastAPI

from shared.database import build_mysql_url, make_engine, make_session_factory, Base
from .routes import build_router

load_dotenv()

app = FastAPI(title="Auth Service", version="1.0.0")

db_url = build_mysql_url(
    host=os.environ["MYSQL_PUBLIC_URL"],
    port=os.environ["MYSQLPORT"],
    user=os.environ["MYSQLUSER"],
    password=os.environ["MYSQLPASSWORD"],
    db=os.environ["MYSQLDATABASE"],
)

engine = make_engine(db_url)
SessionLocal = make_session_factory(engine)

# Creates tables (ok for dev). In prod, better to use migrations.
Base.metadata.create_all(bind=engine)

# ✅ Router (all auth endpoints live here)
app.include_router(build_router(SessionLocal), prefix="/auth", tags=["auth"])


@app.get("/")
def root():
    return {"service": "auth-service", "status": "ok"}


# ✅ Optional: simple docs hints (moved away from /auth/* to avoid confusion)
@app.get("/hints/register", include_in_schema=False)
def register_hint():
    return {
        "message": "Use POST /auth/register",
        "body": {
            "email": "string",
            "password": "string (min 8 chars)"
        }
    }


@app.get("/hints/login", include_in_schema=False)
def login_hint():
    return {
        "message": "Use POST /auth/login",
        "body": {
            "email": "string",
            "password": "string"
        }
    }


@app.get("/hints/verify", include_in_schema=False)
def verify_hint():
    return {
        "message": "Use POST /auth/verify",
        "body": {
            "token": "JWT access token"
        }
    }


@app.get("/health")
def health():
    return {
        "service": "auth-service",
        "status": "ok",
        "endpoints": {
            "register": {
                "method": "POST",
                "path": "/auth/register",
                "description": "Create a new user account"
            },
            "login": {
                "method": "POST",
                "path": "/auth/login",
                "description": "Authenticate user and return JWT token"
            },
            "verify": {
                "method": "POST",
                "path": "/auth/verify",
                "description": "Verify JWT access token"
            },
            "forgot_password": {
                "method": "POST",
                "path": "/auth/forgot-password",
                "description": "Send password reset link to email (token-based)"
            },
            "reset_password": {
                "method": "POST",
                "path": "/auth/reset-password",
                "description": "Validate reset token and update password"
            },
            "google_login": {
                "method": "GET",
                "path": "/auth/google/login",
                "description": "Redirect user to Google OAuth consent screen"
            },
            "google_callback": {
                "method": "GET",
                "path": "/auth/google/callback",
                "description": "Google redirects here with code; returns JWT"
            }
        }
    }
