from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import settings

# Initialize the limiter
# key_func=get_remote_address uses the client's IP address as the identifier
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/minute"] if not settings.is_development else [],
    storage_uri=settings.database_url,
)


def initialize_rate_limit_storage() -> None:
    storage = getattr(limiter, "_storage", None)
    if storage is not None and hasattr(storage, "storage"):
        storage.storage


def close_rate_limit_storage() -> None:
    storage = getattr(limiter, "_storage", None)
    if storage is None:
        return
    storage_client = getattr(storage, "_storage", None)
    if storage_client is not None:
        storage_client.close()


# Modular Rate Limit Profiles
AUTH_LIMIT = "5/minute"
SENSITIVE_LIMIT = "10/minute"
REGULAR_LIMIT = "60/minute"
STRICT_LIMIT = "2/minute"