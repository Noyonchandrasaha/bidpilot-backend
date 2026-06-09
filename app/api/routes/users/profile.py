from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request

from app.api.deps.auth import get_current_user
from app.api.schemas.auth.me import MeResponse
from app.api.schemas.response import APIResponse
from app.core.rate_limit import REGULAR_LIMIT, limiter


router = APIRouter(prefix="/v1/users", tags=["Users"])


@router.get("/me", response_model=APIResponse[MeResponse])
@limiter.limit(REGULAR_LIMIT)
async def get_me(request: Request, user: dict = Depends(get_current_user)):
    payload = MeResponse(
        user_id=str(user["id"]),
        name=user.get("name", ""),
        email=user["email"],
        role=user["role"],
        is_verified=user.get("is_verified", False),
        is_active=user.get("is_active", True),
        created_at=user.get("created_at", datetime.now(timezone.utc)),
        updated_at=user.get("updated_at", datetime.now(timezone.utc)),
        last_login_at=user.get("last_login_at"),
    )
    return APIResponse(status="success", message="User profile retrieved", data=payload)
