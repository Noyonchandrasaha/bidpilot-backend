from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.schemas.response import APIErrorResponse, APIResponse, ErrorDetail
from app.core.config import settings
from app.core.logger import logger
from app.db.connection import db_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting up {settings.APP_NAME} in {settings.ENVIRONMENT} mode...")
    try:
        # Initialize dependencies
        await db_client.connect()
        
        yield
    finally:
        await db_client.close()
        logger.info(f"Shutting down {settings.APP_NAME}...")

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="Production grade FastAPI application",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.EXPOSE_DOCS else None,
        redoc_url="/redoc" if settings.EXPOSE_DOCS else None,
        openapi_url="/openapi.json" if settings.EXPOSE_DOCS else None,
        lifespan=lifespan,
    )

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
    async def health_check():
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


    return app

app = create_app()


