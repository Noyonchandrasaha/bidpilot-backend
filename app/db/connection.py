import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
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
                logger.info("MongoDB connection established.")
            except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
                logger.error(f"Could not connect to MongoDB: {exc}")
                raise Exception(f"Could not connect to MongoDB: {exc}") from exc
        return self.database

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

