from __future__ import annotations

import enum
from datetime import datetime
from decimal import Decimal
from typing import Any

from bson import Decimal128, ObjectId

from app.model.models import new_document_id, to_object_id, utc_now


class Platform(str, enum.Enum):
    FIVERR = "fiverr"
    UPWORK = "upwork"
    DIRECT_CLIENT = "direct_client"


class ServiceType(str, enum.Enum):
    WEBSITE_DEVELOPMENT = "website_development"
    WEB_APPLICATION = "web_application"
    MOBILE_APPLICATION = "mobile_application"
    WEB_AND_MOBILE = "web_and_mobile"
    AUTOMATION = "automation"
    AI_APPLICATION = "ai_application"
    BACKEND_API = "backend_api"
    UI_UX_DESIGN = "ui_ux_design"
    CUSTOM_PROJECT = "custom_project"


class ProjectStatus(str, enum.Enum):
    DRAFT = "draft"
    REQUIREMENT_REVIEW = "requirement_review"
    PROPOSAL_PREPARED = "proposal_prepared"
    PROPOSAL_SENT = "proposal_sent"
    CLIENT_RESPONDED = "client_responded"
    ESTIMATE_PREPARED = "estimate_prepared"
    NEGOTIATION = "negotiation"
    ACTIVE = "active"
    READY_FOR_DELIVERY = "ready_for_delivery"
    COMPLETED = "completed"
    LOST = "lost"
    ARCHIVED = "archived"


class BudgetType(str, enum.Enum):
    UNKNOWN = "unknown"
    FIXED = "fixed"
    RANGE = "range"
    HOURLY = "hourly"


class ContextStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"


class InputSourceType(str, enum.Enum):
    FIVERR_REQUIREMENT = "fiverr_requirement"
    UPWORK_JOB_POST = "upwork_job_post"
    DIRECT_CLIENT_REQUIREMENT = "direct_client_requirement"
    MEETING_NOTE = "meeting_note"
    IMPORTED_DOCUMENT = "imported_document"


class RequirementCategory(str, enum.Enum):
    FUNCTIONAL = "functional"
    NON_FUNCTIONAL = "non_functional"
    TECHNICAL = "technical"
    BUSINESS = "business"
    DESIGN = "design"
    INTEGRATION = "integration"
    SECURITY = "security"
    OTHER = "other"


class RequirementPriority(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RequirementStatus(str, enum.Enum):
    EXTRACTED = "extracted"
    UNCONFIRMED = "unconfirmed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    REMOVED = "removed"


class ContextChangeSource(str, enum.Enum):
    INITIAL_REQUIREMENT = "initial_requirement"
    CLIENT_MESSAGE = "client_message"
    MANUAL_EDIT = "manual_edit"
    DOCUMENT_GENERATION = "document_generation"
    STATUS_CHANGE = "status_change"


class MessageDirection(str, enum.Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class MessageAuthorType(str, enum.Enum):
    CLIENT = "client"
    USER = "user"
    AI = "ai"


class MessageType(str, enum.Enum):
    CLIENT_MESSAGE = "client_message"
    PROFESSIONAL_REPLY = "professional_reply"
    FOLLOW_UP = "follow_up"
    CLARIFICATION = "clarification"
    NEGOTIATION = "negotiation"
    DELIVERY_MESSAGE = "delivery_message"
    INTERNAL_NOTE = "internal_note"


class MessageStatus(str, enum.Enum):
    RECEIVED = "received"
    DRAFT = "draft"
    GENERATED = "generated"
    REVIEWED = "reviewed"
    COPIED = "copied"
    SENT = "sent"
    ARCHIVED = "archived"


class MessageVersionSource(str, enum.Enum):
    ORIGINAL = "original"
    AI = "ai"
    MANUAL = "manual"


class DocumentType(str, enum.Enum):
    REQUIREMENT_SUMMARY = "requirement_summary"
    CUSTOM_OFFER = "custom_offer"
    UPWORK_PROPOSAL = "upwork_proposal"
    DETAILED_PROPOSAL = "detailed_proposal"
    SERVICE_ESTIMATE = "service_estimate"
    SCOPE_OF_WORK = "scope_of_work"
    MILESTONE_PLAN = "milestone_plan"
    PROGRESS_REPORT = "progress_report"
    ORDER_DELIVERY_REPORT = "order_delivery_report"
    PROJECT_HANDOVER = "project_handover"


class DocumentStatus(str, enum.Enum):
    DRAFT = "draft"
    GENERATING = "generating"
    READY_FOR_REVIEW = "ready_for_review"
    FINAL = "final"
    SENT = "sent"
    GENERATION_FAILED = "generation_failed"
    ARCHIVED = "archived"


class ContentType(str, enum.Enum):
    RICH_TEXT = "rich_text"
    PRICING_TABLE = "pricing_table"
    MILESTONE_TABLE = "milestone_table"
    LIST = "list"
    KEY_VALUE = "key_value"


class FileLinkedEntityType(str, enum.Enum):
    PROJECT = "project"
    REQUIREMENT = "requirement"
    MESSAGE = "message"
    DOCUMENT_VERSION = "document_version"
    CREDENTIAL = "credential"


class FileCategory(str, enum.Enum):
    REQUIREMENT_ATTACHMENT = "requirement_attachment"
    CLIENT_DOCUMENT = "client_document"
    REFERENCE_DESIGN = "reference_design"
    MESSAGE_ATTACHMENT = "message_attachment"
    GENERATED_PDF = "generated_pdf"
    FINAL_DELIVERY = "final_delivery"
    CREDENTIAL_ATTACHMENT = "credential_attachment"
    TEMPLATE_ASSET = "template_asset"


class CredentialType(str, enum.Enum):
    API_KEY = "api_key"
    OAUTH = "oauth"
    SERVICE_ACCOUNT = "service_account"
    SSH_KEY = "ssh_key"
    DATABASE = "database"
    HOSTING = "hosting"
    FILE = "file"
    OTHER = "other"


class CredentialEnvironment(str, enum.Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class CredentialStatus(str, enum.Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNVERIFIED = "unverified"


class ActivityActorType(str, enum.Enum):
    USER = "user"
    AI = "ai"
    SYSTEM = "system"


class ActivityEventType(str, enum.Enum):
    PROJECT_CREATED = "project.created"
    PROJECT_STATUS_CHANGED = "project.status_changed"
    REQUIREMENT_UPDATED = "requirement.updated"
    CONTEXT_UPDATED = "context.updated"
    MESSAGE_RECEIVED = "message.received"
    MESSAGE_REPLY_GENERATED = "message.reply_generated"
    MESSAGE_SENT = "message.sent"
    DOCUMENT_GENERATED = "document.generated"
    DOCUMENT_SENT = "document.sent"
    FILE_UPLOADED = "file.uploaded"
    PROJECT_COMPLETED = "project.completed"


def money(value: Decimal | int | float | str | None) -> Decimal128 | None:
    if value is None:
        return None
    return Decimal128(str(Decimal(str(value))))


def create_project_document(
    *,
    owner_id: str | ObjectId,
    project_code: str,
    platform: Platform,
    title: str,
    service_type: ServiceType,
    client: dict[str, Any] | None = None,
    status: ProjectStatus = ProjectStatus.DRAFT,
    budget: dict[str, Any] | None = None,
    deadline: datetime | None = None,
    source: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    return {
        "_id": new_document_id(),
        "owner_id": to_object_id(owner_id),
        "project_code": project_code,
        "platform": platform.value,
        "title": title,
        "client": client or {"name": None, "company_name": None, "external_profile_url": None, "email": None},
        "service_type": service_type.value,
        "status": status.value,
        "budget": normalize_budget(budget),
        "deadline": deadline,
        "source": source or {"job_url": None, "external_job_id": None, "reference": None},
        "tags": tags or [],
        "context": {"status": ContextStatus.PENDING.value, "current_version": 0, "last_analyzed_at": None},
        "statistics": {"message_count": 0, "document_count": 0, "file_count": 0},
        "next_action": {"type": None, "label": None, "due_at": None},
        "last_activity_at": now,
        "created_at": now,
        "updated_at": now,
        "archived_at": None,
        "schema_version": 1,
    }


def normalize_budget(budget: dict[str, Any] | None = None) -> dict[str, Any]:
    budget = budget or {}
    return {
        "type": budget.get("type", BudgetType.UNKNOWN.value),
        "currency": budget.get("currency", "USD"),
        "amount": money(budget.get("amount")),
        "minimum_amount": money(budget.get("minimum_amount")),
        "maximum_amount": money(budget.get("maximum_amount")),
        "hourly_rate": money(budget.get("hourly_rate")),
    }


PROJECT_COLLECTIONS = (
    "projects",
    "project_contexts",
    "project_context_versions",
    "project_messages",
    "project_message_versions",
    "project_documents",
    "project_document_versions",
    "project_files",
    "templates",
    "platform_template_settings",
    "project_credentials",
    "project_activities",
    "sequence_counters",
)
