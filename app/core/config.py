import ast
import logging
from functools import lru_cache
from typing import List, Union, Literal
from pydantic import Field, SecretStr, field_validator, ValidationInfo, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

def get_numeric_log_level(level: str) -> int:
    """
    Convert string log level to numeric value.
    Defaults to INFO if the level is invalid.
    """
    numeric_level = logging._nameToLevel.get(level.upper())
    if numeric_level is None:
        numeric_level = logging.INFO
    return numeric_level

class Settings(BaseSettings):
    """
    Application Settings configured via environment variables.
    """
    APP_NAME: str = Field(default="path_wise", description="Name of the application")
    ENVIRONMENT: Literal["development", "production", "testing"] = Field(default="development", description="Application environment (development, production, testing)")
    LOG_LEVEL: Literal["CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET"] = Field(default="INFO", description='Logging Level ("CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET")')
    CORS_ORIGINS: Union[List[str], str] = Field(default=['*'], description="List of CORS origin or '*' for all")
    TRUSTED_HOSTS: Union[List[str], str] = Field(default=["*"], description="List of trusted hosts or '*' for all")
    EXPOSE_DOCS: bool = Field(default=True, description="Whether to expose OpenAPI documentation.")
    MONGO_DB_CONNECTION_STRING: SecretStr = Field(default=SecretStr(""), description="Write the Mongodb connection string")
    DATABASE_NAME: str = Field(default="path_wise", description="Write the Mongodb Collection String.")
    APP_VERSION: str = Field(default="1.0.0", description="Application version exposed in health and metrics metadata.")
    MONGO_MAX_POOL_SIZE: int = Field(default=50, ge=1, description="Maximum MongoDB connection pool size.")
    MONGO_MIN_POOL_SIZE: int = Field(default=10, ge=0, description="Minimum MongoDB connection pool size.")
    REDIS_URL: str = Field(default="redis://localhost:6379", description="Redis connection URL")
    REDIS_HOST: str = Field(default="", description="Redis host (optional if REDIS_URL is set)")
    REDIS_PORT: int = Field(default=6379, ge=1, le=65535, description="Redis port")
    REDIS_PASSWORD: SecretStr = Field(default=SecretStr(""), description="Redis password")
    REDIS_SSL: bool = Field(default=False, description="This is redis SSL")

    ADMIN_EMAIL: str = Field(default="admin@example.com")
    ADMIN_PASSWORD: str = Field(default="ASDFqwer!234")

    JWT_PRIVATE_KEY: SecretStr = Field(description="This is the Private key of JWT")
    JWT_PUBLIC_KEY: SecretStr = Field(description="This is the public key of jwt")
    JWT_ACTIVE_KID: str = Field(default="v1", description="Active JWT key id (kid)")
    SECRET_PEPPER: SecretStr = Field(description="This is the secret pepper")
    TOKEN_HASH_SECRET: SecretStr = Field(description="Secret used for HMAC hashing refresh tokens")
    JWT_ISSUER:str = Field(default="myapp")
    JWT_AUDIENCE:str = Field(default="myapp_user")
    JWT_LEEWAY_SECONDS:int = Field(default=5)

    ACCESS_TOKEN_EXPIRE_MINUTES:int = Field(default=15)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=30)
    RESET_TOKEN_EXPIRE_MINUTES:int = Field(default=10)

    @field_validator("CORS_ORIGINS", "TRUSTED_HOSTS", mode="before")
    @classmethod
    def assemble_list(cls, v: Union[str, List[str]], info: ValidationInfo) -> Union[List[str], str]:
        """Parse comma-separated string into a list of strings."""
        if isinstance(v, str):
            if v.startswith("["):
                return ast.literal_eval(v)
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @model_validator(mode="after")
    def validate_security_constraints(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            if self.CORS_ORIGINS == ["*"] or self.CORS_ORIGINS == "*":
                raise ValueError("CORS_ORIGINS cannot be '*' in production.")
            if self.TRUSTED_HOSTS == ["*"] or self.TRUSTED_HOSTS == "*":
                raise ValueError("TRUSTED_HOSTS cannot be '*' in production.")
            if self.EXPOSE_DOCS:
                raise ValueError("EXPOSE_DOCS must be False in production.")
        return self


    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT.lower() == 'development'

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )

@lru_cache
def get_settings() -> Settings:
    """
    Get application settings. This function is cached to prevent
    repeatedly reading the .env file and re-validating settings on every function call.
    Uses lru_cache for high-performance dependency injection in FastAPI.
    """
    return Settings()

settings = get_settings()
