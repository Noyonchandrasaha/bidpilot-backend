from __future__ import annotations

from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text

from app.core.config import settings
from app.core.logger import logger


class PostgreSQLClient:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = create_async_engine(
            database_url,
            pool_pre_ping=True,
            future=True,
        )
        self.session_maker = async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )

    @asynccontextmanager
    async def session(self):
        async with self.session_maker() as db_session:
            try:
                yield db_session
                await db_session.commit()
            except Exception:
                await db_session.rollback()
                raise

    async def connect(self):
        try:
            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            logger.info("PostgreSQL connection established.")
        except Exception as exc:
            logger.error("Could not connect to PostgreSQL: %s", exc)
            raise RuntimeError(f"Could not connect to PostgreSQL: {exc}") from exc

    async def ping(self) -> bool:
        try:
            async with self.engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def close(self):
        try:
            logger.info("Closing PostgreSQL connection.")
            await self.engine.dispose()
        except Exception as exc:
            logger.error("Error while closing PostgreSQL connection: %s", exc)


db_client = PostgreSQLClient(settings.database_url)


async def get_database():
    async with db_client.session() as db_session:
        yield db_session
