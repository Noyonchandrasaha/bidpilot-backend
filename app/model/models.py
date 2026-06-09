import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


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


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    users: Mapped[list["User"]] = relationship(back_populates="role")
    permissions: Mapped[list["RolePermission"]] = relationship(back_populates="role", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_roles_slug", "slug"),)


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"
    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    roles: Mapped[list["RolePermission"]] = relationship(back_populates="permission", cascade="all, delete-orphan")
    __table_args__ = (Index("ix_permissions_key", "key"),)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    id: Mapped[uuid.UUID] = uuid_pk()
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    role: Mapped["Role"] = relationship(back_populates="permissions")
    permission: Mapped["Permission"] = relationship(back_populates="roles")
    __table_args__ = (Index("uq_role_permission", "role_id", "permission_id", unique=True), Index("ix_role_permissions_role_id", "role_id"), Index("ix_role_permissions_permission_id", "permission_id"))


class User(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = uuid_pk()
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus, name="user_status"), default=UserStatus.ACTIVE, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    phone: Mapped[str | None] = mapped_column(String(30))
    job_title: Mapped[str | None] = mapped_column(String(100))
    bio: Mapped[str | None] = mapped_column(Text)
    avatar_file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("file_uploads.id", ondelete="SET NULL"), nullable=True)
    role: Mapped["Role"] = relationship(back_populates="users")
    avatar: Mapped["FileUpload | None"] = relationship(foreign_keys=[avatar_file_id], post_update=True)
    profile: Mapped["UserProfile | None"] = relationship(back_populates="user", cascade="all, delete-orphan", uselist=False)
    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    notifications: Mapped[list["Notification"]] = relationship(back_populates="user")
    settings: Mapped[list["Setting"]] = relationship(back_populates="user")
    uploads: Mapped[list["FileUpload"]] = relationship(back_populates="uploaded_by", foreign_keys="FileUpload.uploaded_by_id")
    created_customers: Mapped[list["Customer"]] = relationship(back_populates="created_by", foreign_keys="Customer.created_by_id")
    updated_customers: Mapped[list["Customer"]] = relationship(back_populates="updated_by", foreign_keys="Customer.updated_by_id")
    transactions_created: Mapped[list["CustomerTransaction"]] = relationship(back_populates="created_by", foreign_keys="CustomerTransaction.created_by_id")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="actor", foreign_keys="AuditLog.actor_id")
    __table_args__ = (
        Index("ix_users_role_id", "role_id"),
        Index("ix_users_status", "status"),
        Index("ix_users_created_at", "created_at"),
        Index(
            "uq_users_email_active",
            "email",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class UserProfile(Base, TimestampMixin):
    __tablename__ = "user_profiles"
    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(150))
    timezone: Mapped[str] = mapped_column(String(100), default="Asia/Dhaka", nullable=False)
    language: Mapped[str] = mapped_column(String(20), default="en", nullable=False)
    theme: Mapped[str] = mapped_column(String(30), default="system", nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="BDT", nullable=False)
    date_format: Mapped[str] = mapped_column(String(30), default="YYYY-MM-DD", nullable=False)
    two_factor_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user: Mapped["User"] = relationship(back_populates="profile")


class UserSession(Base, TimestampMixin):
    __tablename__ = "user_sessions"
    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    family_id: Mapped[str] = mapped_column(String(100), nullable=False)
    token_jti: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reused: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    refresh_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(100))
    user_agent: Mapped[str | None] = mapped_column(Text)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    user: Mapped["User"] = relationship(back_populates="sessions")
    __table_args__ = (CheckConstraint("refresh_count >= 0", name="chk_user_sessions_refresh_count_positive"), Index("ix_user_sessions_user_id", "user_id"), Index("ix_user_sessions_session_id", "session_id"), Index("ix_user_sessions_family_id", "family_id"), Index("ix_user_sessions_token_jti", "token_jti"), Index("ix_user_sessions_expires_at", "expires_at"), Index("ix_user_sessions_revoked", "revoked"), Index("ix_user_sessions_reused", "reused"), Index("ix_user_sessions_last_used_at", "last_used_at"))


class CustomerSegment(Base, TimestampMixin):
    __tablename__ = "customer_segments"
    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    color: Mapped[str | None] = mapped_column(String(30))
    description: Mapped[str | None] = mapped_column(Text)
    customers: Mapped[list["Customer"]] = relationship(back_populates="segment")


class Customer(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "customers"
    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str] = mapped_column(String(30), nullable=False)
    whatsapp_number: Mapped[str | None] = mapped_column(String(30))
    status: Mapped[CustomerStatus] = mapped_column(Enum(CustomerStatus, name="customer_status"), default=CustomerStatus.ACTIVE, nullable=False)
    current_balance: Mapped[Decimal] = mapped_column(Numeric(18, 2), default=Decimal("0.00"), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    segment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customer_segments.id", ondelete="SET NULL"), nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    segment: Mapped["CustomerSegment | None"] = relationship(back_populates="customers")
    created_by: Mapped["User | None"] = relationship(back_populates="created_customers", foreign_keys=[created_by_id])
    updated_by: Mapped["User | None"] = relationship(back_populates="updated_customers", foreign_keys=[updated_by_id])
    transactions: Mapped[list["CustomerTransaction"]] = relationship(back_populates="customer")
    files: Mapped[list["FileUpload"]] = relationship(back_populates="customer")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="customer")
    notifications: Mapped[list["Notification"]] = relationship(back_populates="customer")
    __table_args__ = (
        Index("ix_customers_status", "status"),
        Index("ix_customers_segment_id", "segment_id"),
        Index("ix_customers_name", "name"),
        Index("ix_customers_created_at", "created_at"),
        Index(
            "uq_customers_phone_active",
            "phone",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class CustomerTransaction(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "customer_transactions"
    id: Mapped[uuid.UUID] = uuid_pk()
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"), nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    type: Mapped[TransactionType] = mapped_column(Enum(TransactionType, name="transaction_type"), nullable=False)
    status: Mapped[TransactionStatus] = mapped_column(Enum(TransactionStatus, name="transaction_status"), default=TransactionStatus.POSTED, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    reference_no: Mapped[str | None] = mapped_column(String(100))
    notes: Mapped[str | None] = mapped_column(Text)
    transaction_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    balance_before: Mapped[Decimal | None] = mapped_column(Numeric(18, 2))
    balance_after: Mapped[Decimal | None] = mapped_column(Numeric(18, 2))
    reversal_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customer_transactions.id", ondelete="SET NULL"), nullable=True)
    reversed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    customer: Mapped["Customer"] = relationship(back_populates="transactions")
    created_by: Mapped["User | None"] = relationship(back_populates="transactions_created", foreign_keys=[created_by_id])
    reversal_of: Mapped["CustomerTransaction | None"] = relationship(remote_side="CustomerTransaction.id", back_populates="reversed_by")
    reversed_by: Mapped[list["CustomerTransaction"]] = relationship(back_populates="reversal_of")
    attachments: Mapped[list["FileUpload"]] = relationship(back_populates="transaction")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="transaction")
    __table_args__ = (CheckConstraint("amount > 0", name="chk_customer_transaction_amount_positive"), Index("ix_customer_transactions_customer_id", "customer_id"), Index("ix_customer_transactions_created_by_id", "created_by_id"), Index("ix_customer_transactions_status", "status"), Index("ix_customer_transactions_transaction_date", "transaction_date"), Index("ix_customer_transactions_reference_no", "reference_no"), Index("ix_customer_transactions_reversal_of_id", "reversal_of_id"), Index("ix_customer_transactions_created_at", "created_at"))


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"
    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id", ondelete="SET NULL"), nullable=True)
    type: Mapped[NotificationType] = mapped_column(Enum(NotificationType, name="notification_type"), default=NotificationType.INFO, nullable=False)
    status: Mapped[NotificationStatus] = mapped_column(Enum(NotificationStatus, name="notification_status"), default=NotificationStatus.UNREAD, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    action_url: Mapped[str | None] = mapped_column(String(500))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user: Mapped["User"] = relationship(back_populates="notifications")
    customer: Mapped["Customer | None"] = relationship(back_populates="notifications")
    __table_args__ = (Index("ix_notifications_user_id", "user_id"), Index("ix_notifications_customer_id", "customer_id"), Index("ix_notifications_status", "status"), Index("ix_notifications_type", "type"), Index("ix_notifications_created_at", "created_at"))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = uuid_pk()
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id", ondelete="SET NULL"), nullable=True)
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customer_transactions.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[AuditAction] = mapped_column(Enum(AuditAction, name="audit_action"), nullable=False)
    entity: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(100))
    before: Mapped[dict | None] = mapped_column(JSONB)
    after: Mapped[dict | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(String(100))
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(String(100))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor: Mapped["User | None"] = relationship(back_populates="audit_logs", foreign_keys=[actor_id])
    customer: Mapped["Customer | None"] = relationship(back_populates="audit_logs")
    transaction: Mapped["CustomerTransaction | None"] = relationship(back_populates="audit_logs")
    __table_args__ = (Index("ix_audit_logs_actor_id", "actor_id"), Index("ix_audit_logs_customer_id", "customer_id"), Index("ix_audit_logs_transaction_id", "transaction_id"), Index("ix_audit_logs_entity_entity_id", "entity", "entity_id"), Index("ix_audit_logs_request_id", "request_id"), Index("ix_audit_logs_created_at", "created_at"))


class FileUpload(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "file_uploads"
    id: Mapped[uuid.UUID] = uuid_pk()
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id", ondelete="SET NULL"), nullable=True)
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customer_transactions.id", ondelete="SET NULL"), nullable=True)
    type: Mapped[FileType] = mapped_column(Enum(FileType, name="file_type"), default=FileType.ATTACHMENT, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    checksum: Mapped[str | None] = mapped_column(String(128))
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSONB)
    uploaded_by: Mapped["User | None"] = relationship(back_populates="uploads", foreign_keys=[uploaded_by_id])
    customer: Mapped["Customer | None"] = relationship(back_populates="files")
    transaction: Mapped["CustomerTransaction | None"] = relationship(back_populates="attachments")
    __table_args__ = (CheckConstraint("file_size > 0", name="chk_file_upload_size_positive"), Index("ix_file_uploads_uploaded_by_id", "uploaded_by_id"), Index("ix_file_uploads_customer_id", "customer_id"), Index("ix_file_uploads_transaction_id", "transaction_id"), Index("ix_file_uploads_type", "type"), Index("ix_file_uploads_created_at", "created_at"))


class Setting(Base, TimestampMixin):
    __tablename__ = "settings"
    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    scope: Mapped[SettingScope] = mapped_column(Enum(SettingScope, name="setting_scope"), nullable=False)
    key: Mapped[str] = mapped_column(String(150), nullable=False)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    user: Mapped["User | None"] = relationship(back_populates="settings")
    __table_args__ = (Index("ix_settings_user_id", "user_id"), Index("ix_settings_scope", "scope"), Index("uq_settings_system_key", "key", unique=True, postgresql_where=(scope == SettingScope.SYSTEM)), Index("uq_settings_user_key", "user_id", "key", unique=True, postgresql_where=(scope == SettingScope.USER)))
