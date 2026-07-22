from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, TEXT

from app.core.config import settings
from app.core.logger import logger


class MongoDBClient:
    def __init__(self, database_url: str, database_name: str):
        self.database_url = database_url
        self.database_name = database_name
        self.client: AsyncIOMotorClient | None = None
        self.database: AsyncIOMotorDatabase | None = None

    async def connect(self) -> None:
        try:
            self.client = AsyncIOMotorClient(self.database_url, tz_aware=True)
            self.database = self.client[self.database_name]
            await self.client.admin.command("ping")
            await self.create_indexes()
            logger.info("MongoDB connection established.")
        except Exception as exc:
            logger.error("Could not connect to MongoDB: %s", exc)
            raise RuntimeError(f"Could not connect to MongoDB: {exc}") from exc

    async def create_indexes(self) -> None:
        db = self.get_database()
        await db.roles.create_index("slug", unique=True)
        await db.roles.create_index("name", unique=True)
        await db.users.create_index(
            [("email", ASCENDING)],
            unique=True,
            partialFilterExpression={"deleted_at": None},
        )
        await db.users.create_index("role_id")
        await db.user_sessions.create_index("token_hash", unique=True)
        await db.user_sessions.create_index("session_id", unique=True)
        await db.user_sessions.create_index("family_id")
        await db.user_sessions.create_index("user_id")
        await db.user_sessions.create_index("expires_at", expireAfterSeconds=0)
        await db.revoked_tokens.create_index("jti", unique=True)
        await db.revoked_tokens.create_index("expires_at", expireAfterSeconds=0)
        await db.password_resets.create_index("reset_id", unique=True)
        await db.password_resets.create_index("expires_at", expireAfterSeconds=0)
        await self.create_project_indexes()

    async def create_project_indexes(self) -> None:
        db = self.get_database()
        await db.projects.create_index([("owner_id", ASCENDING), ("project_code", ASCENDING)], unique=True)
        await db.projects.create_index(
            [
                ("owner_id", ASCENDING),
                ("platform", ASCENDING),
                ("status", ASCENDING),
                ("updated_at", DESCENDING),
            ]
        )
        await db.projects.create_index(
            [("owner_id", ASCENDING), ("status", ASCENDING), ("deadline", ASCENDING)]
        )
        await db.projects.create_index([("owner_id", ASCENDING), ("last_activity_at", DESCENDING)])
        await db.projects.create_index(
            [("title", TEXT), ("client.name", TEXT), ("client.company_name", TEXT), ("tags", TEXT)],
            name="project_text_search",
        )

        await db.project_contexts.create_index("project_id", unique=True)
        await db.project_context_versions.create_index(
            [("project_id", ASCENDING), ("version_number", ASCENDING)],
            unique=True,
        )

        await db.project_messages.create_index([("project_id", ASCENDING), ("occurred_at", DESCENDING)])
        await db.project_messages.create_index(
            [("project_id", ASCENDING), ("status", ASCENDING), ("occurred_at", DESCENDING)]
        )
        await db.project_message_versions.create_index(
            [("message_id", ASCENDING), ("version_number", ASCENDING)],
            unique=True,
        )

        await db.project_documents.create_index([("project_id", ASCENDING), ("updated_at", DESCENDING)])
        await db.project_documents.create_index(
            [("project_id", ASCENDING), ("document_type", ASCENDING), ("status", ASCENDING)]
        )
        await db.project_document_versions.create_index(
            [("document_id", ASCENDING), ("version_number", ASCENDING)],
            unique=True,
        )

        await db.project_files.create_index([("project_id", ASCENDING), ("created_at", DESCENDING)])
        await db.project_files.create_index(
            [("linked_entity.type", ASCENDING), ("linked_entity.id", ASCENDING)]
        )
        await db.project_activities.create_index([("project_id", ASCENDING), ("occurred_at", DESCENDING)])

        await db.templates.create_index("code", unique=True)
        await db.templates.create_index([("platform", ASCENDING), ("is_active", ASCENDING)])
        await db.platform_template_settings.create_index(
            [("owner_id", ASCENDING), ("platform", ASCENDING)],
            unique=True,
        )

    async def ping(self) -> bool:
        try:
            if self.client is None:
                return False
            await self.client.admin.command("ping")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self.client is not None:
            logger.info("Closing MongoDB connection.")
            self.client.close()
            self.client = None
            self.database = None

    def get_database(self) -> AsyncIOMotorDatabase:
        if self.database is None:
            raise RuntimeError("MongoDB client is not connected.")
        return self.database


db_client = MongoDBClient(settings.database_url, settings.DATABASE_NAME)


async def get_database() -> AsyncIOMotorDatabase:
    yield db_client.get_database()