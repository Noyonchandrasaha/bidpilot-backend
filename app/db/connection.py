from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING

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
