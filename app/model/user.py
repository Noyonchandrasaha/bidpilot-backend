from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
from datetime import datetime, timezone
from bson import ObjectId
from enum import Enum
from app.utils.py_object_id import PyObjectId
from app.utils.enum.user import UserRole


# -----------------------------------
# Database User Model
# -----------------------------------

class User(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    full_name: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    hashed_password: str
    role: UserRole 
    is_verified: bool = Field(default=False)
    is_active:bool = Field(default=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
    )
