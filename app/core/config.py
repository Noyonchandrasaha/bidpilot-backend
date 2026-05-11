import ast
import logging
from functools import lru_cache
from typing import List, Union, Literal
from pydantic import Field, SecretStr, field_validator, ValidationInfo
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
    APP_NAME: str = Field(default="rohitcanindica", description="Name of the application")
    ENVIRONMENT: Literal["development", "production", "testing"] = Field(default="development", description="Application environment (development, production, testing)")
    LOG_LEVEL: Literal["CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET"] = Field(default="INFO", description='Logging Level ("CRITICAL", "INFO", "ERROR", "WARNING", "DEBUG", "NOTSET")')
    CORS_ORIGINS: Union[List[str], str] = Field(default=['*'], description="List of CORS origin or '*' for all")
    TRUSTED_HOSTS: Union[List[str], str] = Field(default=["*"], description="List of trusted hosts or '*' for all")
    EXPOSE_DOCS: bool = Field(default=True, description="Whether to expose OpenAPI documentation.")
    MONGO_DB_CONNECTION_STRING: SecretStr = Field(default=SecretStr(""), description="Write the Mongodb connection string")
    DATABASE_NAME: str = Field(default="icepots", description="Write the Mongodb Collection String.")
    APP_VERSION: str = Field(default="1.0.0", description="Application version exposed in health and metrics metadata.")
    MONGO_MAX_POOL_SIZE: int = Field(default=50, ge=1, description="Maximum MongoDB connection pool size.")
    MONGO_MIN_POOL_SIZE: int = Field(default=10, ge=0, description="Minimum MongoDB connection pool size.")

    @field_validator("CORS_ORIGINS", "TRUSTED_HOSTS", mode="before")
    @classmethod
    def assemble_list(cls, v: Union[str, List[str]], info: ValidationInfo) -> Union[List[str], str]:
        """Parse comma-separated string into a list of strings."""
        if isinstance(v, str):
            if v.startswith("["):
                return ast.literal_eval(v)
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


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
