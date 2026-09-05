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
    """Initialize built-in app signatures."""
    from db.models import AppSignature

    builtin_apps = [
        {
            "app_name": "tiktok",
            "display_name": "TikTok",
            "domains": [
                "*.tiktok.com",
                "*.tiktokcdn.com",
                "*.musical.ly",
                "*.bytedance.com",
                "*.bytecdn.cn",
                "*.byteoversea.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "instagram",
            "display_name": "Instagram",
            "domains": [
                "*.instagram.com",
                "*.cdninstagram.com",
                "*.ig.me",
                "*.igcdn.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "youtube",
            "display_name": "YouTube",
            "domains": [
                "*.youtube.com",
                "*.youtu.be",
                "*.ytimg.com",
                "*.googlevideo.com",
                "*.youtube-nocookie.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "snapchat",
            "display_name": "Snapchat",
            "domains": [
                "*.snapchat.com",
                "*.snap.com",
                "*.snapads.com",
                "*.sc-cdn.net",
                "*.sc-static.net",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "facebook",
            "display_name": "Facebook",
            "domains": [
                "*.facebook.com",
                "*.fbcdn.net",
                "*.fb.com",
                "*.fb.me",
                "*.fbsbx.com",
                "*.messenger.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "twitter",
            "display_name": "Twitter/X",
            "domains": [
                "*.twitter.com",
                "*.twimg.com",
                "*.t.co",
                "*.x.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "netflix",
            "display_name": "Netflix",
            "domains": [
                "*.netflix.com",
                "*.nflxvideo.net",
                "*.nflximg.net",
                "*.nflxext.com",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "discord",
            "display_name": "Discord",
            "domains": [
                "*.discord.com",
                "*.discord.gg",
                "*.discordapp.com",
                "*.discordapp.net",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "twitch",
            "display_name": "Twitch",
            "domains": [
                "*.twitch.tv",
                "*.ttvnw.net",
                "*.jtvnw.net",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
        {
            "app_name": "whatsapp",
            "display_name": "WhatsApp",
            "domains": [
                "*.whatsapp.com",
                "*.whatsapp.net",
            ],
            "ip_ranges": [],
            "is_builtin": True,
        },
    ]

    if async_session_factory is None:
        raise RuntimeError("Database is not configured")
    async with async_session_factory() as session:
        for app_data in builtin_apps:
            from sqlalchemy import select
            result = await session.execute(
                select(AppSignature).where(AppSignature.app_name == app_data["app_name"])
            )
            existing = result.scalar_one_or_none()

            if not existing:
                signature = AppSignature(**app_data)
                session.add(signature)

        await session.commit()


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
