from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
)


# =========================================================
# USER ROLE ENUM
# =========================================================

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"


# =========================================================
# SIGN IN REQUEST
# =========================================================

class SigninRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered user email address",
        examples=["john@example.com"],
    )

    password: SecretStr = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User account password"
    )

    remember_me: bool = Field(
        default=False,
        description="Whether to extend refresh token lifetime"
    )

    device_name: Optional[str] = Field(
        default=None,
        max_length=120,
        description="Optional client device name"
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "email": "john@example.com",
                "password": "StrongPass@123",
                "remember_me": True,
                "device_name": "MacBook Pro Chrome"
            }
        }
    )


# =========================================================
# USER INFO
# =========================================================

class UserInfo(BaseModel):
    user_id: str = Field(
        ...,
        description="Unique user identifier",
        examples=["665d1234567890abcdef9999"]
    )


    role: UserRole = Field(
        ...,
        description="User role"
    )

    is_verified: bool = Field(
        ...,
        description="Whether the user's email is verified"
    )

    last_login_at: Optional[datetime] = Field(
        default=None,
        description="Last successful login timestamp"
    )

    model_config = ConfigDict(
        extra="forbid"
    )


# =========================================================
# AUTH TOKENS
# =========================================================

class AuthTokens(BaseModel):
    access_token: str = Field(
        ...,
        description="JWT access token"
    )

    refresh_token: str = Field(
        ...,
        description="JWT refresh token"
    )

    token_type: str = Field(
        default="Bearer",
        description="Authentication scheme"
    )

    access_token_expires_in: int = Field(
        ...,
        description="Access token expiry time in seconds",
        examples=[3600]
    )

    refresh_token_expires_in: int = Field(
        ...,
        description="Refresh token expiry time in seconds",
        examples=[2592000]
    )

    session_id: str = Field(
        ...,
        description="Unique login session identifier"
    )

    issued_at: datetime = Field(
        default_factory=datetime.now(timezone),
        description="Token issuance timestamp"
    )

    model_config = ConfigDict(
        extra="forbid"
    )



# =========================================================
# SIGN IN RESPONSE
# =========================================================

class SigninResponse(BaseModel):
    data: UserInfo = Field(
        ...,
        description="Authenticated user information"
    )

    tokens: Optional[AuthTokens] = Field(
        default=None,
        description="Authentication tokens"
    )

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Login successful",
                "timestamp": "2026-05-18T10:30:00Z",
                "request_id": "req_123456",

                "data": {
                    "user_id": "665d1234567890abcdef9999",
                    "role": "STUDENT",
                    "is_verified": True,
                    "last_login_at": "2026-05-17T12:00:00Z"
                },

                "tokens": {
                    "access_token": "jwt-access-token",
                    "refresh_token": "jwt-refresh-token",
                    "token_type": "Bearer",
                    "access_token_expires_in": 3600,
                    "refresh_token_expires_in": 2592000,
                    "session_id": "session_uuid",
                    "issued_at": "2026-05-18T10:30:00Z"
                }

            }
        }
    )