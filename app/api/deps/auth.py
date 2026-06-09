from typing import Callable
import json
from datetime import datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from redis.exceptions import ConnectionError as RedisConnectionError

from app.db.connection import get_database
from app.model.models import User
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
    payload["id"] = str(payload.get("id"))
    for field in ("created_at", "updated_at", "last_login_at"):
        value = payload.get(field)
        if isinstance(value, datetime):
            payload[field] = value.isoformat()
    return json.dumps(payload)


def _deserialize_user_from_cache(raw: str) -> dict:
    payload = json.loads(raw)
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
    db: AsyncSession = Depends(get_database),
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
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    await security_service.set_rls_context(db, user_id=user_id, bypass=False)

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
        result = await db.execute(select(User).options(selectinload(User.role)).where(User.id == user_id))
        user_obj = result.scalar_one_or_none()
        if user_obj:
            user = {
                "id": str(user_obj.id),
                "name": user_obj.name,
                "email": user_obj.email,
                "role": user_obj.role.slug if getattr(user_obj, "role", None) else None,
                "is_active": user_obj.status.value == "ACTIVE",
                "is_verified": user_obj.email_verified,
                "created_at": user_obj.created_at,
                "updated_at": user_obj.updated_at,
                "last_login_at": user_obj.last_login_at,
            }
            await security_service.set_rls_context(
                db,
                user_id=str(user_obj.id),
                role=user_obj.role.slug if getattr(user_obj, "role", None) else "user",
                bypass=False,
            )
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
