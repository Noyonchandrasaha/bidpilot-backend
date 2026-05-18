from datetime import datetime, timezone
from typing import Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
)

import re


# =========================================================
# STEP-1
# INITIATE FORGOT PASSWORD FLOW
# =========================================================

class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        description="Registered user email address",
        examples=["john@example.com"]
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "email": "john@example.com"
            }
        }
    )


class ForgotPasswordResponse(BaseModel):
    reset_token: str = Field(
        ...,
        description=(
            "Temporary JWT token for password reset flow. "
            "Contains flow metadata only."
        )
    )

    expires_in: int = Field(
        default=300,
        description="Reset token expiration time in seconds",
        examples=[300]
    )

    retry_after: int = Field(
        default=60,
        description="Time in seconds before requesting another OTP",
        examples=[60]
    )

    otp_sent: bool = Field(
        default=True,
        description="Indicates whether OTP delivery was initiated"
    )

    model_config = ConfigDict(
        extra="forbid"
    )


# =========================================================
# STEP-2
# VERIFY OTP
# =========================================================

class OTPVerificationRequest(BaseModel):
    otp: str = Field(
        ...,
        min_length=6,
        max_length=6,
        description="6-character OTP code",
        examples=["AC1EV3"]
    )

    reset_token: str = Field(
        ...,
        description="JWT reset session token"
    )

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, value: str) -> str:
        value = value.strip().upper()

        if not re.fullmatch(r"^[A-Z0-9]{6}$", value):
            raise ValueError(
                "OTP must contain only uppercase letters and numbers"
            )

        return value

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "otp": "AC1EV3",
                "reset_token": "jwt_token_here"
            }
        }
    )


class OTPVerificationResponse(BaseModel):
    verified: bool = Field(
        default=True,
        description="OTP verification status"
    )

    verified_reset_token: str = Field(
        ...,
        description=(
            "Short-lived JWT token allowing password reset"
        )
    )

    expires_in: int = Field(
        default=600,
        description="Verification token expiration time in seconds"
    )

    remaining_attempts: Optional[int] = Field(
        default=None,
        description="Remaining OTP verification attempts"
    )

    model_config = ConfigDict(
        extra="forbid"
    )


# =========================================================
# STEP-3
# RESEND OTP
# =========================================================

class ResendOTPRequest(BaseModel):
    reset_token: str = Field(
        ...,
        description="JWT reset session token"
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "reset_token": "jwt_token_here"
            }
        }
    )


class ResendOTPResponse(BaseModel):
    reset_token: str = Field(
        ...,
        description="Updated JWT reset session token"
    )

    expires_in: int = Field(
        default=300,
        description="Reset token expiration time in seconds"
    )

    retry_after: int = Field(
        default=60,
        description="Cooldown before requesting another OTP"
    )

    otp_resent: bool = Field(
        default=True,
        description="Indicates whether OTP resend was successful"
    )

    model_config = ConfigDict(
        extra="forbid"
    )


# =========================================================
# STEP-4
# UPDATE PASSWORD
# =========================================================

class UpdatePasswordRequest(BaseModel):
    verified_reset_token: str = Field(
        ...,
        description=(
            "Verified JWT token obtained after OTP verification"
        )
    )

    new_password: SecretStr = Field(
        ...,
        min_length=8,
        max_length=128,
        description=(
            "New password. "
            "Must contain uppercase, lowercase, number, "
            "and special character."
        )
    )

    confirm_password: SecretStr = Field(
        ...,
        description="Must match the new password"
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(
        cls,
        value: SecretStr
    ) -> SecretStr:

        password = value.get_secret_value()

        if len(password) < 8:
            raise ValueError(
                "Password must be at least 8 characters long"
            )

        if not re.search(r"[A-Z]", password):
            raise ValueError(
                "Password must contain at least one uppercase letter"
            )

        if not re.search(r"[a-z]", password):
            raise ValueError(
                "Password must contain at least one lowercase letter"
            )

        if not re.search(r"\d", password):
            raise ValueError(
                "Password must contain at least one number"
            )

        if not re.search(r"[!@#$%^&*()_\-+=<>?/{}~|]", password):
            raise ValueError(
                "Password must contain at least one special character"
            )

        return value

    @field_validator("confirm_password")
    @classmethod
    def validate_password_match(
        cls,
        value: SecretStr,
        info
    ) -> SecretStr:

        new_password = info.data.get("new_password")

        if (
            new_password
            and value.get_secret_value()
            != new_password.get_secret_value()
        ):
            raise ValueError("Passwords do not match")

        return value

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "verified_reset_token": "jwt_token_here",
                "new_password": "StrongPass123!",
                "confirm_password": "StrongPass123!"
            }
        }
    )


class UpdatePasswordResponse(BaseModel):
    password_updated: bool = Field(
        default=True,
        description="Indicates whether password was updated"
    )

    sessions_revoked: bool = Field(
        default=True,
        description="Indicates whether all active sessions were revoked"
    )

    updated_at: datetime = Field(
        default_factory=datetime.now(timezone.utc),
        description="Password update timestamp"
    )

    model_config = ConfigDict(
        extra="forbid"
    )

