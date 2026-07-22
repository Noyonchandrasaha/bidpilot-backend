from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db.connection import get_database
from app.utils.enum.user import UserRole
from app.utils.security import (
    InvalidTokenClaimsError,
    InvalidTokenTypeError,
    TokenExpiredError,
    TokenRevokedError,
    security_service,
)


async def get_current_user(
    request: Request,
    db: AsyncIOMotorDatabase = Depends(get_database),
) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing access token")

    try:
        payload = await security_service.verify_access_token(token)
    except (InvalidTokenClaimsError, InvalidTokenTypeError, TokenExpiredError, TokenRevokedError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user_doc = await db.users.find_one({"_id": user_id, "deleted_at": None})
    role_doc = await db.roles.find_one({"_id": user_doc.get("role_id")}) if user_doc else None
    user = None
    if user_doc:
        user = {
            "id": str(user_doc["_id"]),
            "name": user_doc.get("name", ""),
            "email": user_doc["email"],
            "role": role_doc["slug"] if role_doc else "user",
            "is_active": user_doc.get("status") == "ACTIVE",
            "is_verified": user_doc.get("email_verified", False),
            "created_at": user_doc.get("created_at"),
            "updated_at": user_doc.get("updated_at"),
            "last_login_at": user_doc.get("last_login_at"),
        }

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not user.get("is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")

    return user


def require_roles(*allowed_roles: UserRole) -> Callable:
    async def role_checker(user: dict = Depends(get_current_user)) -> dict:
        role_value = user.get("role")
        allowed_values = {role.value for role in allowed_roles}
        if role_value not in allowed_values:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return role_checker
