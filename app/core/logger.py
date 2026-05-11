import logging
import sys
from app.core.config import settings

def setup_logging(level: str, app_name: str, environment: str) -> logging.Logger:
    """
    Configure application logging.
    """
    logger = logging.getLogger(app_name)
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(log_format)

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    def get_numeric_log_level(level: str) -> int:
        numeric_level = logging._nameToLevel.get(level.upper())
        if numeric_level is None:
            numeric_level = logging.INFO
        return numeric_level
    
    logger.setLevel(get_numeric_log_level(level))
    
    logger.propagate = False
    logger.debug(f"Application '{app_name}' logging initialized in {environment} mode")
    return logger

logger = setup_logging(settings.LOG_LEVEL, settings.APP_NAME, settings.ENVIRONMENT)