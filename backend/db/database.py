"""Database connection and session management."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import AppConfig
from db.models import Base

engine: AsyncEngine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None
_config: AppConfig | None = None


def configure_database(config: AppConfig) -> None:
    """Create database resources explicitly during application startup."""
    global engine, async_session_factory, _config
    if engine is not None:
        raise RuntimeError("Database is already configured")
    config.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{config.db_path}", echo=False)
    _config = config

    @event.listens_for(engine.sync_engine, "connect")
    def enable_foreign_keys(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )


async def init_db():
    """Initialize database and create tables."""
    if engine is None or _config is None:
        raise RuntimeError("Database is not configured")
    from db.migrations import migrate_database
    await migrate_database(engine, _config)

    # Initialize default app signatures
    await init_app_signatures()


async def init_app_signatures():
    """Refresh built-in signatures from the validated shipped catalog."""
    from db.catalog import import_catalog
    if _config is None:
        raise RuntimeError("Database is not configured")
    async with get_session() as session:
        await import_catalog(session, _config.app_signatures_file)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get async database session."""
    if async_session_factory is None:
        raise RuntimeError("Database is not configured")
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_db():
    """Close database connections."""
    global engine, async_session_factory
    if engine is not None:
        await engine.dispose()
    engine = None
    async_session_factory = None
