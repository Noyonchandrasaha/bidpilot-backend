from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field
from app.utils.py_object_id import PyObjectId

class RefreshSession(BaseModel):
    """
    Enterprise-grade refresh token session model.
    """
    session_id: str = Field(
        ...,
        description="Unique session identifier"
    )
    user_id: PyObjectId = Field(
        ...,
        description="User Id owning this session"
    )
    family_id: str = Field(
        ...,
        description=(
            "Refresh token family ID"
            "used for rotation/replay detection"
        )
    )
    token_jti: str = Field(
        ...,
        description="JWT ID of refresh token"
    )
    token_hash: str = Field(
        ...,
        description="HMAC/SHA256 hashed refesh token"
    )
    revoked: bool = Field(
        default=False,
        description="Replay attact detected"
    )
    ip_address: Optional[str] = Field(
        default=None,
        description="Client IP address"
    )
    user_agent: Optional[str] = Field(
        default=None,
        description="Raw user-agent string"
    )
    device_family: Optional[str] = Field(
        default=None,
        description="Chrome, Safari, etc.",
    )

    browser_family: Optional[str] = Field(
        default=None,
        description="Browser family",
    )

    os_family: Optional[str] = Field(
        default=None,
        description="Operating system",
    )

    is_mobile: bool = Field(
        default=False,
        description="Whether device is mobile",
    )
    created_at: datetime = Field(
        default_factory=lambda:
            datetime.now(timezone.utc),
    )

    last_used_at: datetime = Field(
        default_factory=lambda:
            datetime.now(timezone.utc),
    )

    expires_at: datetime = Field(
        ...,
        description="TTL expiration timestamp",
    )

    revoked_at: Optional[datetime] = Field(
        default=None,
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "session_id":
                    "5bdb7c7c-f6b0",

                "user_id":
                    "user_123",

                "family_id":
                    "family_abc",

                "token_jti":
                    "jwt_jti",

                "token_hash":
                    "hashed_refresh_token",

                "revoked": False,

                "reused": False,

                "ip_address":
                    "192.168.1.1",

                "browser_family":
                    "Chrome",

                "os_family":
                    "Windows",

                "is_mobile": False,
            }
        }
    }