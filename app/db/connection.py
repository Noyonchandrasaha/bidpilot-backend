import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING, IndexModel
from pymongo.collation import Collation
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from app.core.config import settings
from app.core.logger import logger

class MongoDBClient:
    def __init__(
        self,
        mongodb_uri,
        db_name: str,
        max_pool_size: int = 50,
        min_pool_size: int = 10,
    ):
        self.mongodb_uri = mongodb_uri
        self.db_name = db_name
        self.client: AsyncIOMotorClient | None = None
        self.database = None
        self.max_pool_size = max_pool_size
        self.min_pool_size = min_pool_size

    async def connect(self):
        if not self.client:
            try:
                mongodb_uri_str = self.mongodb_uri.get_secret_value()
                self.client = AsyncIOMotorClient(
                    mongodb_uri_str,
                    maxPoolSize=self.max_pool_size,
                    minPoolSize=self.min_pool_size,
                    serverSelectionTimeoutMS=5000,
                    socketTimeoutMS=5000,
                )

                await self.client.admin.command("ping")
                self.database = self.client[self.db_name]
                await self.ensure_indexes()
                logger.info("MongoDB connection established.")
            except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
                logger.error(f"Could not connect to MongoDB: {exc}")
                raise Exception(f"Could not connect to MongoDB: {exc}") from exc
        return self.database

    async def ensure_indexes(self):
        if self.database is None:
            raise Exception("Database not initialized. Call connect() first.")

        # users collection indexes
        await self.database.users.create_indexes([
            IndexModel(
                [("email", ASCENDING)],
                name="uq_users_email",
                unique=True,
                collation=Collation(locale="en", strength=2),
            ),
            IndexModel(
                [("role", ASCENDING), ("is_active", ASCENDING)],
                name="ix_users_role_active",
            ),
        ])

        # students collection indexes
        await self.database.students.create_indexes([
            IndexModel(
                [("user_id", ASCENDING)],
                name="uq_students_user_id",
                unique=True,
            ),
            IndexModel(
                [("created_at", DESCENDING)],
                name="ix_students_created_at_desc",
            ),
        ])

        # refresh_sessions collection indexes
        await self.database.refresh_sessions.create_indexes([
            IndexModel(
                [("session_id", ASCENDING)],
                name="uq_refresh_session_id",
                unique=True,
            ),
            IndexModel(
                [("token_jti", ASCENDING)],
                name="uq_refresh_token_jti",
                unique=True,
            ),
            IndexModel(
                [("token_hash", ASCENDING)],
                name="uq_refresh_token_hash",
                unique=True,
            ),
            IndexModel(
                [("user_id", ASCENDING), ("family_id", ASCENDING), ("revoked", ASCENDING)],
                name="ix_refresh_user_family_revoked",
            ),
            IndexModel(
                [("user_id", ASCENDING), ("revoked", ASCENDING), ("expires_at", ASCENDING)],
                name="ix_refresh_user_revoked_exp",
            ),
            IndexModel(
                [("expires_at", ASCENDING)],
                name="ttl_refresh_expires_at",
                expireAfterSeconds=0,
            ),
        ])

    async def ping(self) -> bool:
        if not self.client:
            return False
        try:
            await self.client.admin.command("ping")
        except Exception:
            return False
        return True

    async def close(self):
        if self.client:
            try:
                logger.info("Closing MongoDB connection.")
                self.client.close()
                self.client = None
                self.database = None
            except Exception as exc:
                logger.error("Error while closing MongoDB connection: %s", exc)
        else:
            logger.warning("MongoDB client is not initialized, skipping close.")

    def get_database(self):
        if self.database is None:
            raise Exception("Database not initialized. Call connect() first.")
        return self.database

db_client = MongoDBClient(
    settings.MONGO_DB_CONNECTION_STRING,
    settings.DATABASE_NAME,
    max_pool_size=settings.MONGO_MAX_POOL_SIZE,
    min_pool_size=settings.MONGO_MIN_POOL_SIZE,
)


def get_database():
    return db_client.get_database()

