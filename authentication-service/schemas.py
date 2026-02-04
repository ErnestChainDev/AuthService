from pydantic import BaseModel, EmailStr, Field, field_validator

MAX_BCRYPT_BYTES = 72

# -------------------------
# Auth (Register / Login)
# -------------------------

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def bcrypt_max_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_BCRYPT_BYTES:
            raise ValueError("Password too long (max 72 bytes for bcrypt).")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def bcrypt_max_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_BCRYPT_BYTES:
            raise ValueError("Password too long (max 72 bytes for bcrypt).")
        return v


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VerifyIn(BaseModel):
    token: str


class VerifyOut(BaseModel):
    sub: str
    email: str


# -------------------------
# Forgot / Reset Password
# -------------------------

class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def bcrypt_max_bytes(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_BCRYPT_BYTES:
            raise ValueError("Password too long (max 72 bytes for bcrypt).")
        return v


class GenericMsgOut(BaseModel):
    detail: str
