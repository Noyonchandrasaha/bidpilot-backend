from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request, status, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.api.schemas.response import APIErrorResponse, APIResponse, ErrorDetail
from app.core.config import settings
from app.core.logger import logger
from app.db.connection import db_client
from app.model.models import UserStatus, new_document_id
from user_agents import parse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.rate_limit import limiter, REGULAR_LIMIT
from app.utils.security import security_service
from app.api.routes.auth.signin import router as auth_router
from app.api.routes.users.profile import router as user_router


async def seed_admin_account() -> None:
    admin_email = settings.ADMIN_EMAIL.strip().lower()
    admin_password = settings.ADMIN_PASSWORD.strip()

    if not admin_email or not admin_password:
        logger.warning("admin_seed_skipped_missing_credentials")
        return

    now = datetime.now(timezone.utc)
    db = db_client.get_database()
    admin_role = await db.roles.find_one({"slug": "admin"})
    if admin_role is None:
        admin_role = {
            "_id": new_document_id(),
            "name": "Admin",
            "slug": "admin",
            "description": "System administrator role",
            "is_system": True,
            "created_at": now,
            "updated_at": now,
        }
        await db.roles.insert_one(admin_role)

    existing_admin = await db.users.find_one({"email": admin_email})
    admin_payload = {
        "role_id": admin_role["_id"],
        "name": "System Admin",
        "email": admin_email,
        "password_hash": security_service.hash_password(admin_password),
        "status": UserStatus.ACTIVE.value,
        "email_verified": True,
        "updated_at": now,
        "deleted_at": None,
    }
    if existing_admin:
        await db.users.update_one(
            {"_id": existing_admin["_id"]},
            {"$set": admin_payload},
        )
        logger.info("admin_seed_updated_existing", extra={"email": admin_email})
        return

    admin_payload["_id"] = new_document_id()
    admin_payload["created_at"] = now
    await db.users.insert_one(admin_payload)
    logger.info("admin_seed_created", extra={"email": admin_email})


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting up {settings.APP_NAME} in {settings.ENVIRONMENT} mode...")
    try:
        # Initialize dependencies
        await db_client.connect()
        await seed_admin_account()
        
        yield
    finally:
        await db_client.close()
        logger.info(f"Shutting down {settings.APP_NAME}...")

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="BidPilot_backend API",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.EXPOSE_DOCS else None,
        redoc_url="/redoc" if settings.EXPOSE_DOCS else None,
        openapi_url="/openapi.json" if settings.EXPOSE_DOCS else None,
        lifespan=lifespan,
    )

    # Rate Limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Hide server details
        if "server" in response.headers:
             del response.headers["server"]
        return response

    @app.middleware("http")
    async def log_user_agent(request: Request, call_next):
        ua_string = request.headers.get("User-Agent", "")
        user_agent = parse(ua_string)
        request.state.user_agent_raw = ua_string
        request.state.device_name = (
            f"{user_agent.device.family} | "
            f"{user_agent.browser.family} {user_agent.browser.version_string} | "
            f"{user_agent.os.family} {user_agent.os.version_string}"
        )
        
        # Log basic info
        client_ip = request.client.host if request.client else "unknown"
        logger.info(
            f"Incoming Request | IP: {client_ip} | Method: {request.method} | Path: {request.url.path} | "
            f"Browser: {user_agent.browser.family} {user_agent.browser.version_string} | "
            f"OS: {user_agent.os.family} {user_agent.os.version_string} | "
            f"Device: {user_agent.device.family} | PC: {user_agent.is_pc} | Mobile: {user_agent.is_mobile}"
        )
        
        # Log all available data for the user to see in logger (as requested)
        logger.debug(
            f"Full User-Agent Data: "
            f"Browser: {user_agent.browser}, "
            f"OS: {user_agent.os}, "
            f"Device: {user_agent.device}, "
            f"Mobile: {user_agent.is_mobile}, "
            f"Tablet: {user_agent.is_tablet}, "
            f"PC: {user_agent.is_pc}, "
            f"Touch: {user_agent.is_touch_capable}, "
            f"Bot: {user_agent.is_bot}"
        )
        
        response = await call_next(request)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        response = APIErrorResponse(
            status="error",
            message=str(exc.detail),
            error_code=f"HTTP_{exc.status_code}_ERROR",
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=response.model_dump(exclude_none=True),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        details = [
            ErrorDetail(
                loc=[str(loc) for loc in error.get("loc", [])],
                msg=error.get("msg", ""),
                type=error.get("type", ""),
            )
            for error in exc.errors()
        ]

        response = APIErrorResponse(
            status="error",
            message="Validation error in request parameters",
            error_code="VALIDATION_ERROR",
            details=details,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=response.model_dump(exclude_none=True),
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        message = str(exc) if not settings.is_production else "An unexpected internal server error occurred."
        response = APIErrorResponse(
            status="error",
            message=message,
            error_code="INTERNAL_SERVER_ERROR",
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=response.model_dump(exclude_none=True),
        )

    @app.get("/", include_in_schema=False)
    async def root():
        if settings.EXPOSE_DOCS:
            return RedirectResponse(url="/docs")
        return APIResponse(status="success", message=f"Welcome to {settings.APP_NAME} API")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/health", response_model=APIResponse[dict], tags=["System"])
    @limiter.limit(REGULAR_LIMIT)
    async def health_check(request: Request):
        return APIResponse(
            status="success",
            message="Application is healthy and running",
            data={
                "environment": settings.ENVIRONMENT,
                "version": settings.APP_VERSION,
            },
        )

    @app.get("/health/ready", response_model=APIResponse[dict], tags=["System"])
    async def readiness_check():
        db_ready = await db_client.ping()
        status_code = status.HTTP_200_OK if db_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        payload = APIResponse(
            status="success" if db_ready else "error",
            message="Application dependencies are ready" if db_ready else "Database dependency is unavailable",
            data={"database": "up" if db_ready else "down"},
        )
        return JSONResponse(status_code=status_code, content=payload.model_dump(exclude_none=True))


    # Include API routers
    app.include_router(auth_router)
    app.include_router(user_router)


    return app

app = create_app()


