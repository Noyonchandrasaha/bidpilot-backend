from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.schemas.auth.signin import SigninRequest, SigninResponse
from app.api.schemas.response import APIResponse
from app.db.connection import get_database
from app.services.auth_service import auth_service
from app.utils.security import InvalidCredentialsError
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
