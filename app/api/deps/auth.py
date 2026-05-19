from typing import Callable

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.exceptions import ConnectionError as RedisConnectionError

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
    except RedisConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable",
        )
    except (InvalidTokenClaimsError, InvalidTokenTypeError, TokenExpiredError, TokenRevokedError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token")

    user_id = payload.get("sub")
    if not user_id or not ObjectId.is_valid(user_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user = await db.users.find_one({"_id": ObjectId(user_id)})
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
