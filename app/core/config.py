import ast
import logging
import os
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
    APP_NAME: str = Field(default="BidPilot_backend", description="Name of the application")
    ENVIRONMENT: Literal["development", "production", "testing"] = Field(default="development", description="Application environment (development, production, testing)")
    LOG_LEVEL: Literal["CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET"] = Field(default="INFO", description='Logging Level ("CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET")')
    CORS_ORIGINS: Union[List[str], str] = Field(default=['*'], description="List of CORS origin or '*' for all")
    TRUSTED_HOSTS: Union[List[str], str] = Field(default=["*"], description="List of trusted hosts or '*' for all")
    EXPOSE_DOCS: bool = Field(default=True, description="Whether to expose OpenAPI documentation.")
    DATABASE_URL: SecretStr = Field(default=SecretStr("mongodb://localhost:27017"), description="MongoDB connection URL.")
    DATABASE_NAME: str = Field(default="BidPilot_backend", description="MongoDB database name.")
    APP_VERSION: str = Field(default="1.0.0", description="Application version exposed in health and metrics metadata.")

    PM_EMAIL: str = Field(default="pm@example.com")
    PM_PASSWORD: str = Field(default="ASDFqwer!234")

    JWT_PRIVATE_KEY: SecretStr = Field(description="This is the Private key of JWT")
    JWT_PUBLIC_KEY: SecretStr = Field(description="This is the public key of jwt")
    JWT_ACTIVE_KID: str = Field(default="v1", description="Active JWT key id (kid)")
    SECRET_PEPPER: SecretStr = Field(description="This is the secret pepper")
    TOKEN_HASH_SECRET: SecretStr = Field(default=SecretStr(""), description="Secret used for HMAC hashing refresh tokens")
    JWT_ISSUER:str = Field(default="BidPilot_backend")
    JWT_AUDIENCE:str = Field(default="BidPilot_backend_user")
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
        required_secrets = {
            "JWT_PRIVATE_KEY": self.JWT_PRIVATE_KEY.get_secret_value().strip(),
            "JWT_PUBLIC_KEY": self.JWT_PUBLIC_KEY.get_secret_value().strip(),
            "SECRET_PEPPER": self.SECRET_PEPPER.get_secret_value().strip(),
            "TOKEN_HASH_SECRET": self.token_hash_secret,
        }
        missing_secrets = [name for name, value in required_secrets.items() if not value]
        if missing_secrets:
            raise ValueError(f"Missing required security settings: {', '.join(missing_secrets)}")

        if self.ENVIRONMENT == "production":
            if self.CORS_ORIGINS == ["*"] or self.CORS_ORIGINS == "*":
                raise ValueError("CORS_ORIGINS cannot be '*' in production.")
            if self.TRUSTED_HOSTS == ["*"] or self.TRUSTED_HOSTS == "*":
                raise ValueError("TRUSTED_HOSTS cannot be '*' in production.")
            if self.EXPOSE_DOCS:
                raise ValueError("EXPOSE_DOCS must be False in production.")
            if self.PM_EMAIL == "pm@example.com" or self.PM_PASSWORD == "ASDFqwer!234":
                raise ValueError("Default PM credentials cannot be used in production.")
        return self

    @property
    def database_url(self) -> str:
        return self.DATABASE_URL.get_secret_value().strip()

    @property
    def token_hash_secret(self) -> str:
        value = self.TOKEN_HASH_SECRET.get_secret_value().strip()
        if value:
            return value
        return os.getenv("TOKEN_HASH_SECRET", "").strip()


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

def get_settings() -> Settings:
    """
    Get application settings from environment variables.
    """
    return Settings()

settings = get_settings()
