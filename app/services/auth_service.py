from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.schemas.auth.signin import AuthTokens, SigninRequest, SigninResponse, UserInfo
from app.utils.security import InvalidCredentialsError, security_service


class AuthService:
    @staticmethod
    async def signin(*, db: AsyncIOMotorDatabase, payload: SigninRequest, request: Request) -> SigninResponse:
        email = payload.email.strip().lower()
        user = await db.users.find_one({"email": email, "deleted_at": None})

        # Avoid user enumeration by returning the same auth error path.
        if not user:
            raise InvalidCredentialsError("Invalid email or password")

        if user.get("status") != "ACTIVE":
            raise InvalidCredentialsError("Invalid email or password")

        is_valid_password = security_service.verify_password(
            payload.password.get_secret_value(),
            user["password_hash"],
        )
        if not is_valid_password:
            raise InvalidCredentialsError("Invalid email or password")

        role = await db.roles.find_one({"_id": user.get("role_id")})
        role_slug = role["slug"] if role else "user"

        client_host = request.client.host if request.client else None
        middleware_device_name = getattr(request.state, "device_name", None)
        raw_user_agent = getattr(request.state, "user_agent_raw", None)
        user_agent = raw_user_agent or request.headers.get("user-agent")

        refresh_token, session_id = await security_service.create_refresh_token(
            db=db,
            user_id=str(user["_id"]),
            ip_address=client_host,
            user_agent=middleware_device_name or user_agent,
        )
        access_token = security_service.create_access_token(
            user_id=str(user["_id"]),
            session_id=session_id,
        )

        now = datetime.now(timezone.utc)
        await db.users.update_one({"_id": user["_id"]}, {"$set": {"updated_at": now, "last_login_at": now}})

        return SigninResponse(
            data=UserInfo(
                user_id=str(user["_id"]),
                role=role_slug,
                is_verified=user.get("email_verified", False),
                last_login_at=now,
            ),
            tokens=AuthTokens(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="Bearer",
                access_token_expires_in=security_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                refresh_token_expires_in=security_service.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                session_id=session_id,
                issued_at=now,
            ),
        )

    @staticmethod
    async def refresh_tokens(*, db: AsyncIOMotorDatabase, refresh_token: str, request: Request) -> dict[str, Any]:
        client_host = request.client.host if request.client else None
        middleware_device_name = getattr(request.state, "device_name", None)
        raw_user_agent = getattr(request.state, "user_agent_raw", None)
        user_agent = raw_user_agent or request.headers.get("user-agent")

        access_token, new_refresh_token = await security_service.rotate_refresh_token(
            db=db,
            refresh_token=refresh_token,
            ip_address=client_host,
            user_agent=middleware_device_name or user_agent,
        )

        payload = security_service.decode_token(new_refresh_token)
        session = await db.user_sessions.find_one({"token_hash": security_service.hash_token(new_refresh_token)})
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "session_id": payload.get("sid"),
            "refresh_count": session.get("refresh_count", 0) if session else 0,
            "access_token_expires_in": security_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token_expires_in": security_service.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        }


auth_service = AuthService()
