"""Ordered SQLite migrations. Back up existing databases before changing schema."""

import asyncio
from datetime import datetime, timezone
import os
import sqlite3
import json
from uuid import uuid4

from sqlalchemy import delete, select, text

from config import AppConfig
from db.models import AdminCredential, Base, DeviceEnforcement, Setting

SCHEMA_VERSION = 5


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
    if version < 2:
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(access_logs)"))}
        if "event_id" not in columns:
            connection.execute(text("ALTER TABLE access_logs ADD COLUMN event_id VARCHAR(64)"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_access_logs_event_id ON access_logs(event_id)"))
        connection.execute(text("UPDATE schema_version SET version=2 WHERE id=1"))
    if version < 3:
        from utils.rules import canonical_rule
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(device_rules)"))}
        for name in ("canonical_value", "validation_error"):
            if name not in columns:
                connection.execute(text(f"ALTER TABLE device_rules ADD COLUMN {name} VARCHAR(255)"))
        seen = {}
        rows = connection.execute(text("SELECT id,device_id,rule_type,rule_value,is_active FROM device_rules ORDER BY id")).mappings().all()
        for row in rows:
            try:
                key, value = canonical_rule(row["rule_type"], json.loads(row["rule_value"]))
            except (ValueError, KeyError, TypeError, AttributeError):
                connection.execute(text("UPDATE device_rules SET canonical_value=:key, validation_error='Invalid legacy rule; edit or remove this rule' WHERE id=:id"), {"key": f"legacy:{row['id']}", "id": row["id"]})
                continue
            identity = (row["device_id"], row["rule_type"], key)
            if identity in seen:
                retained = seen[identity]
                if row["is_active"]:
                    if row["rule_type"] == "bandwidth" and retained["active"]:
                        value = {name: min(value[name], retained["value"][name]) for name in value}
                    connection.execute(text("UPDATE device_rules SET is_active=1,rule_value=:value WHERE id=:id"), {"value": json.dumps(value), "id": retained["id"]})
                    retained.update(active=True, value=value)
                connection.execute(text("DELETE FROM device_rules WHERE id=:id"), {"id": row["id"]})
            else:
                connection.execute(text("UPDATE device_rules SET canonical_value=:key,rule_value=:value WHERE id=:id"), {"key": key, "value": json.dumps(value), "id": row["id"]})
                seen[identity] = {"id": row["id"], "value": value, "active": bool(row["is_active"])}
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_device_rule_identity ON device_rules(device_id,rule_type,canonical_value)"))
        connection.execute(text("UPDATE schema_version SET version=3 WHERE id=1"))
    if version < 4:
        DeviceEnforcement.__table__.create(connection, checkfirst=True)
        connection.execute(text("UPDATE schema_version SET version=4 WHERE id=1"))
    if version < 5:
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(access_logs)"))}
        for name, sql_type in (
            ("rule_id", "INTEGER"),
            ("protocol", "VARCHAR(32)"),
            ("reason", "VARCHAR(255)"),
        ):
            if name not in columns:
                connection.execute(text(f"ALTER TABLE access_logs ADD COLUMN {name} {sql_type}"))
        connection.execute(text("UPDATE schema_version SET version=5 WHERE id=1"))
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
