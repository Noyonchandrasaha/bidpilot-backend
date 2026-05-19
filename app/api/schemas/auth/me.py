from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.utils.enum.user import UserRole


class MeResponse(BaseModel):
    user_id: str = Field(..., description="Authenticated user id")
    full_name: str = Field(..., description="User full name")
    email: EmailStr = Field(..., description="User email")
    role: UserRole = Field(..., description="User role")
    is_verified: bool = Field(..., description="Email verification status")
    is_active: bool = Field(..., description="Account active status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last account update timestamp")
    last_login_at: Optional[datetime] = Field(default=None, description="Last successful login timestamp")

    model_config = ConfigDict(extra="forbid")
