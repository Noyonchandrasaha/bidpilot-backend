from typing import Callable
import json
from datetime import datetime

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
    redis_client,
)

USER_PROFILE_CACHE_TTL_SECONDS = 60


def _serialize_user_for_cache(user: dict) -> str:
    payload = dict(user)
    payload["_id"] = str(payload.get("_id"))
    for field in ("created_at", "updated_at", "last_login_at"):
        value = payload.get(field)
        if isinstance(value, datetime):
            payload[field] = value.isoformat()
    return json.dumps(payload)


def _deserialize_user_from_cache(raw: str) -> dict:
    payload = json.loads(raw)
    if payload.get("_id") and ObjectId.is_valid(payload["_id"]):
        payload["_id"] = ObjectId(payload["_id"])
    for field in ("created_at", "updated_at", "last_login_at"):
        value = payload.get(field)
        if isinstance(value, str):
            try:
                payload[field] = datetime.fromisoformat(value)
            except ValueError:
                pass
    return payload


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

    cache_key = f"user_profile:{user_id}"
    user = None
    try:
        cached_user = await redis_client.get(cache_key)
        if cached_user:
            user = _deserialize_user_from_cache(cached_user)
    except RedisConnectionError:
        # Cache is optional for this flow; fallback to database.
        user = None

    if user is None:
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            try:
                await redis_client.setex(
                    cache_key,
                    USER_PROFILE_CACHE_TTL_SECONDS,
                    _serialize_user_for_cache(user),
                )
            except RedisConnectionError:
                pass

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
