import enum
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class UserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"


class CustomerStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ARCHIVED = "ARCHIVED"


class TransactionType(str, enum.Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class TransactionStatus(str, enum.Enum):
    POSTED = "POSTED"
    PENDING = "PENDING"
    REVERSED = "REVERSED"
    VOID = "VOID"


class NotificationType(str, enum.Enum):
    INFO = "INFO"
    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"


class NotificationStatus(str, enum.Enum):
    UNREAD = "UNREAD"
    READ = "READ"


class FileType(str, enum.Enum):
    AVATAR = "AVATAR"
    DOCUMENT = "DOCUMENT"
    EXPORT = "EXPORT"
    ATTACHMENT = "ATTACHMENT"


class SettingScope(str, enum.Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"


class AuditAction(str, enum.Enum):
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    RESTORE = "RESTORE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    EXPORT = "EXPORT"
    IMPORT = "IMPORT"
    REVERSE_TRANSACTION = "REVERSE_TRANSACTION"
    VOID_TRANSACTION = "VOID_TRANSACTION"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_document_id() -> str:
    return str(uuid4())


def serialize_document(document: dict[str, Any] | None) -> dict[str, Any] | None:
    if document is None:
        return None
    payload = dict(document)
    payload["id"] = str(payload.pop("_id"))
    return payload
