"""Ordered SQLite migrations. Back up existing databases before changing schema."""

import asyncio
from datetime import datetime, timezone
import os
import sqlite3
from uuid import uuid4

from sqlalchemy import delete, select, text

from config import AppConfig
from db.models import AdminCredential, Base, Setting

SCHEMA_VERSION = 1


def _backup_if_needed(config: AppConfig) -> None:
    path = config.db_path
    if not path.exists() or path.stat().st_size == 0:
        return
    with sqlite3.connect(path) as source:
        exists = source.execute("SELECT 1 FROM sqlite_master WHERE name='schema_version'").fetchone()
        version = source.execute("SELECT version FROM schema_version WHERE id=1").fetchone() if exists else None
        current = version[0] if version else 0
        if current > SCHEMA_VERSION:
            raise RuntimeError("Database schema is newer than this application; use the matching version")
        if current == SCHEMA_VERSION:
            return
        backup = path.with_name(f"{path.name}.backup-{uuid4().hex}.db")
        descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with sqlite3.connect(backup) as target:
            source.backup(target)


def _migrate(connection, config: AppConfig) -> None:
    connection.execute(text("CREATE TABLE IF NOT EXISTS schema_version (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)"))
    version = connection.execute(text("SELECT version FROM schema_version WHERE id=1")).scalar_one_or_none() or 0
    if version > SCHEMA_VERSION:
        raise RuntimeError("Database schema is newer than this application")
    seed = config.auth_password_hash
    if version < 1:
        # Version 1 adds private auth tables; legacy device/rule/log tables retain
        # their original IDs and columns. Future column upgrades belong here.
        Base.metadata.create_all(connection)
        saved = connection.execute(select(Setting.value).where(Setting.key == "password_hash")).scalar_one_or_none()
        seed = saved or config.auth_password_hash
        connection.execute(delete(Setting).where(Setting.key == "password_hash"))
        connection.execute(text("INSERT INTO schema_version (id,version) VALUES (1,1) ON CONFLICT(id) DO UPDATE SET version=1"))
    credential = connection.execute(select(AdminCredential.id)).first()
    if credential is None and seed:
        connection.execute(AdminCredential.__table__.insert().values(
            id=1, username=config.auth_username, password_hash=seed,
            version=1, updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))


async def migrate_database(engine, config: AppConfig) -> None:
    await asyncio.to_thread(_backup_if_needed, config)
    async with engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            await connection.run_sync(_migrate, config)
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
