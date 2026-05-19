from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from datetime import datetime, timezone
from redis.exceptions import ConnectionError as RedisConnectionError

from app.api.schemas.auth.signin import SigninRequest, SigninResponse
from app.api.schemas.auth.forget_password import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    OTPVerificationRequest,
    OTPVerificationResponse,
    ResendOTPRequest,
    ResendOTPResponse,
    UpdatePasswordRequest,
    UpdatePasswordResponse,
)
from app.api.schemas.response import APIResponse
from app.db.connection import get_database
from app.services.auth_service import auth_service
from app.services.forgot_password_service import forgot_password_service
from app.utils.security import (
    InvalidCredentialsError,
    InvalidSessionError,
    TokenReuseDetectedError,
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenClaimsError,
    InvalidTokenTypeError,
    security_service,
)
from app.core.rate_limit import AUTH_LIMIT, limiter


router = APIRouter(prefix="/v1/auth", tags=["Auth"])


@router.post("/signin", response_model=APIResponse[SigninResponse])
@limiter.limit(AUTH_LIMIT)
async def signin(
    request: Request,
    response: Response,
    payload: SigninRequest,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    try:
        result = await auth_service.signin(db=db, payload=payload, request=request)
        if result.tokens:
            access_max_age = result.tokens.access_token_expires_in
            refresh_max_age = result.tokens.refresh_token_expires_in
            secure_cookie = request.url.scheme == "https"

            response.set_cookie(
                key="access_token",
                value=result.tokens.access_token,
                max_age=access_max_age,
                httponly=True,
                secure=secure_cookie,
                samesite="lax",
                path="/",
            )
            response.set_cookie(
                key="refresh_token",
                value=result.tokens.refresh_token,
                max_age=refresh_max_age,
                httponly=True,
                secure=secure_cookie,
                samesite="lax",
                path="/",
            )

        safe_payload = SigninResponse(
            data=result.data,
            tokens=None,
        )
        return APIResponse(status="success", message="Signin successful", data=safe_payload.model_dump())
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.post("/signout", response_model=APIResponse[dict])
@limiter.limit(AUTH_LIMIT)
async def signout(
    request: Request,
    response: Response,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        try:
            payload = await security_service.verify_refresh_token(db=db, token=refresh_token)
            session_id = payload.get("sid")
            if session_id:
                await security_service.revoke_session(db=db, session_id=session_id)
        except (InvalidSessionError, InvalidTokenClaimsError, InvalidTokenTypeError, TokenRevokedError, TokenExpiredError):
            pass

    if access_token:
        try:
            access_payload = security_service.decode_token(access_token)
            if access_payload.get("type") == security_service.ACCESS_TOKEN_TYPE:
                exp = access_payload.get("exp")
                if isinstance(exp, (int, float)):
                    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                    await security_service.revoke_access_token(
                        jti=access_payload["jti"],
                        expires_at=expires_at,
                    )
        except Exception:
            pass

    secure_cookie = request.url.scheme == "https"
    response.delete_cookie("access_token", path="/", httponly=True, secure=secure_cookie, samesite="lax")
    response.delete_cookie("refresh_token", path="/", httponly=True, secure=secure_cookie, samesite="lax")

    return APIResponse(
        status="success",
        message="Signout successful",
        data={"signed_out": True},
    )


@router.post("/refresh", response_model=APIResponse[dict])
@limiter.limit(AUTH_LIMIT)
async def refresh_tokens(
    request: Request,
    response: Response,
    db: AsyncIOMotorDatabase = Depends(get_database),
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token cookie is missing",
        )

    try:
        rotated = await auth_service.refresh_tokens(
            db=db,
            refresh_token=refresh_token,
            request=request,
        )
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except TokenReuseDetectedError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reuse detected")
    except (InvalidSessionError, InvalidTokenClaimsError, InvalidTokenTypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    secure_cookie = request.url.scheme == "https"
    response.set_cookie(
        key="access_token",
        value=rotated["access_token"],
        max_age=rotated["access_token_expires_in"],
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=rotated["refresh_token"],
        max_age=rotated["refresh_token_expires_in"],
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )

    return APIResponse(
        status="success",
        message="Token refresh successful",
        data={
            "refreshed": True,
            "session_id": rotated["session_id"],
            "refresh_count": rotated["refresh_count"],
            "access_token_expires_in": rotated["access_token_expires_in"],
            "refresh_token_expires_in": rotated["refresh_token_expires_in"],
        },
    )


@router.post("/forgot-password", response_model=APIResponse[ForgotPasswordResponse])
@limiter.limit(AUTH_LIMIT)
async def forgot_password(request: Request, payload: ForgotPasswordRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    try:
        result = await forgot_password_service.request_reset(db=db, email=payload.email)
        return APIResponse(status="success", message="If the account exists, OTP has been generated", data=result)
    except RedisConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password reset service is temporarily unavailable",
        )


@router.post("/forgot-password/verify-otp", response_model=APIResponse[OTPVerificationResponse])
@limiter.limit(AUTH_LIMIT)
async def verify_forgot_password_otp(request: Request, payload: OTPVerificationRequest):
    try:
        result = await forgot_password_service.verify_otp(otp=payload.otp, reset_token=payload.reset_token)
        return APIResponse(status="success", message="OTP verified successfully", data=result)
    except RedisConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OTP verification service is temporarily unavailable",
        )


@router.post("/forgot-password/resend-otp", response_model=APIResponse[ResendOTPResponse])
@limiter.limit(AUTH_LIMIT)
async def resend_forgot_password_otp(request: Request, payload: ResendOTPRequest):
    try:
        result = await forgot_password_service.resend_otp(reset_token=payload.reset_token)
        return APIResponse(status="success", message="OTP resent successfully", data=result)
    except RedisConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OTP resend service is temporarily unavailable",
        )


@router.post("/forgot-password/update-password", response_model=APIResponse[UpdatePasswordResponse])
@limiter.limit(AUTH_LIMIT)
async def update_forgot_password(request: Request, payload: UpdatePasswordRequest, db: AsyncIOMotorDatabase = Depends(get_database)):
    try:
        result = await forgot_password_service.update_password(
            db=db,
            verified_reset_token=payload.verified_reset_token,
            new_password=payload.new_password.get_secret_value(),
        )
        return APIResponse(status="success", message="Password updated successfully", data=result)
    except RedisConnectionError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password update service is temporarily unavailable",
        )
