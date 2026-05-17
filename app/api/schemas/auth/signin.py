from pydantic import BaseModel, Field, EmailStr, ConfigDict
from datetime import datetime


# -----------------------------------
# Sign In Request
# -----------------------------------

class SigninRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered user email address",
        examples=["john@example.com"],
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User account password",
        examples=["StrongPass@123"],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "john@example.com",
                "password": "StrongPass@123"
            }
        }
    )


# -----------------------------------
# User Info
# -----------------------------------

class UserInfo(BaseModel):
    user_id: str = Field(
        ...,
        description="Unique user identifier",
        examples=["665d1234567890abcdef9999"]
    )

    role: str = Field(
        ...,
        description="User role",
        examples=["STUDENT"]
    )

    is_verified: bool = Field(
        ...,
        description="Whether the user email is verified"
    )



# -----------------------------------
# Token Payload
# -----------------------------------

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

    expires_in: int = Field(
        ...,
        description="Access token expiration time in seconds",
        examples=[3600]
    )


# -----------------------------------
# Sign In Response
# -----------------------------------

class SigninResponse(BaseModel):

    data: UserInfo
    tokens: AuthTokens

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "data": {
                    "user_id": "665d1234567890abcdef9999",
                    "role": "STUDENT",
                    "is_verified": True
                },
                "tokens": {
                    "access_token": "jwt-access-token",
                    "refresh_token": "jwt-refresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }
            }
        }
    )