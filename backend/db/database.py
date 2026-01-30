"""Database connection and session management."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import DB_PATH, DATA_DIR
from db.models import Base

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Create async engine
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
)

# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db():
    """Initialize database and create tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

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
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def close_db():
    """Close database connections."""
    await engine.dispose()
