from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.schemas.auth.signin import AuthTokens, SigninRequest, SigninResponse, UserInfo
from app.model.models import User, UserSession
from app.utils.security import InvalidCredentialsError, security_service


class AuthService:
    @staticmethod
    async def signin(*, db: AsyncSession, payload: SigninRequest, request: Request) -> SigninResponse:
        email = payload.email.strip().lower()
        await security_service.set_rls_context(db, bypass=True)
        result = await db.execute(select(User).options(selectinload(User.role)).where(User.email == email))
        user = result.scalar_one_or_none()

        # Avoid user enumeration by returning the same auth error path.
        if not user:
            raise InvalidCredentialsError("Invalid email or password")

        if user.status.value != "ACTIVE":
            raise InvalidCredentialsError("Invalid email or password")

        is_valid_password = security_service.verify_password(
            payload.password.get_secret_value(),
            user.password_hash,
        )
        if not is_valid_password:
            raise InvalidCredentialsError("Invalid email or password")

        client_host = request.client.host if request.client else None
        middleware_device_name = getattr(request.state, "device_name", None)
        raw_user_agent = getattr(request.state, "user_agent_raw", None)
        user_agent = raw_user_agent or request.headers.get("user-agent")

        refresh_token, session_id = await security_service.create_refresh_token(
            db=db,
            user_id=str(user.id),
            ip_address=client_host,
            user_agent=middleware_device_name or user_agent,
        )
        access_token = security_service.create_access_token(
            user_id=str(user.id),
            session_id=session_id,
        )

        now = datetime.now(timezone.utc)
        await security_service.set_rls_context(db, user_id=str(user.id), role=user.role.slug if getattr(user, "role", None) else "user", bypass=False)
        await db.execute(update(User).where(User.id == user.id).values(updated_at=now, last_login_at=now))
        await db.commit()

        return SigninResponse(
            data=UserInfo(
                user_id=str(user.id),
                role=user.role.slug if getattr(user, "role", None) else "user",
                is_verified=user.email_verified,
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
    async def refresh_tokens(*, db: AsyncSession, refresh_token: str, request: Request) -> dict[str, Any]:
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
        result = await db.execute(select(UserSession).where(UserSession.token_hash == security_service.hash_token(new_refresh_token)))
        session = result.scalar_one_or_none()
        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "session_id": payload.get("sid"),
            "refresh_count": getattr(session, "refresh_count", 0),
            "access_token_expires_in": security_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token_expires_in": security_service.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        }


auth_service = AuthService()
