import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from config import load_config
from db import database
from db.models import Base


@pytest.mark.asyncio
async def test_legacy_password_migration_preserves_data_and_beats_bootstrap(tmp_path):
    path = tmp_path / "parental_control.db"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE settings (key VARCHAR(100) PRIMARY KEY, value TEXT, updated_at DATETIME);
            INSERT INTO settings VALUES ('password_hash', 'legacy-hash', NULL);
            INSERT INTO settings VALUES ('theme', 'dark', NULL);
        """)
    config = load_config(None, {"data_dir": tmp_path, "auth_password_hash": "bootstrap-hash"})
    database.configure_database(config)
    try:
        await database.init_db()
        async with database.get_session() as session:
            credential = (await session.execute(text("SELECT password_hash FROM admin_credentials"))).scalar_one()
            assert credential == "legacy-hash"
            assert (await session.execute(text("SELECT value FROM settings WHERE key='theme'"))).scalar_one() == "dark"
            assert (await session.execute(text("SELECT value FROM settings WHERE key='password_hash'"))).first() is None
            assert (await session.execute(text("PRAGMA foreign_keys"))).scalar_one() == 1
        backups = list(tmp_path.glob("parental_control.db.backup-*.db"))
        assert len(backups) == 1
        with sqlite3.connect(backups[0]) as connection:
            assert connection.execute("SELECT value FROM settings WHERE key='password_hash'").fetchone()[0] == "legacy-hash"
        await database.init_db()
        assert len(list(tmp_path.glob("parental_control.db.backup-*.db"))) == 1
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_restart_does_not_overwrite_saved_credential(tmp_path):
    config = load_config(None, {"data_dir": tmp_path, "auth_password_hash": "first-seed"})
    database.configure_database(config)
    try:
        await database.init_db()
    finally:
        await database.close_db()
    config = config.model_copy(update={"auth_password_hash": "other-seed"})
    database.configure_database(config)
    try:
        await database.init_db()
        async with database.get_session() as session:
            assert (await session.execute(text("SELECT password_hash FROM admin_credentials"))).scalar_one() == "first-seed"
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_reviewed_schema_migration_preserves_devices_rules_and_logs(tmp_path):
    with sqlite3.connect(tmp_path / "parental_control.db") as connection:
        connection.executescript((Path(__file__).parent / "fixtures/legacy.sql").read_text())
        connection.execute("INSERT INTO devices (id,mac_address,friendly_name,is_blocked,is_monitored) VALUES (41,'AA:BB:CC:DD:EE:FF','Kids tablet',1,0)")
        connection.execute("INSERT INTO device_rules (id,device_id,rule_type,rule_value,is_active) VALUES (51,41,'block_domain',?,1)", ('{"domain":"example.test"}',))
        connection.execute("INSERT INTO access_logs (id,device_id,domain,action) VALUES (61,41,'example.test','blocked')")
        connection.execute("INSERT INTO bandwidth_logs (id,device_id,bytes_sent,bytes_received) VALUES (71,41,123,456)")
    database.configure_database(load_config(None, {"data_dir": tmp_path}))
    try:
        await database.init_db()
        async with database.get_session() as session:
            assert (await session.execute(text("SELECT id,friendly_name,is_blocked,is_monitored FROM devices"))).one() == (41, "Kids tablet", 1, 0)
            assert (await session.execute(text("SELECT id,device_id,is_active FROM device_rules"))).one() == (51, 41, 1)
            assert (await session.execute(text("SELECT id,device_id,domain FROM access_logs"))).one() == (61, 41, "example.test")
            assert (await session.execute(text("SELECT id,bytes_sent,bytes_received FROM bandwidth_logs"))).one() == (71, 123, 456)
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_bootstrap_can_seed_an_initialized_database_without_a_credential(tmp_path):
    database.configure_database(load_config(None, {"data_dir": tmp_path, "auth_password_hash": ""}))
    try:
        await database.init_db()
    finally:
        await database.close_db()
    database.configure_database(load_config(None, {"data_dir": tmp_path, "auth_password_hash": "later-seed"}))
    try:
        await database.init_db()
        async with database.get_session() as session:
            assert (await session.execute(text("SELECT password_hash FROM admin_credentials"))).scalar_one() == "later-seed"
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_version_three_database_adds_enforcement_state_without_losing_intent(tmp_path):
    path = tmp_path / "parental_control.db"
    sync_engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(sync_engine)
    sync_engine.dispose()
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            DROP TABLE device_enforcement;
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL
            );
            INSERT INTO schema_version VALUES (1, 3);
            INSERT INTO devices (
                id, mac_address, is_monitored, is_blocked, is_online
            ) VALUES (81, 'AA:BB:CC:DD:EE:81', 1, 0, 0);
        """)

    database.configure_database(load_config(None, {"data_dir": tmp_path}))
    try:
        await database.init_db()
        async with database.get_session() as session:
            assert (await session.execute(text("SELECT version FROM schema_version"))).scalar_one() == 4
            columns = {
                row[1]
                for row in (await session.execute(text("PRAGMA table_info(device_enforcement)")))
            }
            assert {"device_id", "component", "state", "last_error", "updated_at"} <= columns
            assert (
                await session.execute(
                    text("SELECT is_monitored,is_blocked FROM devices WHERE id=81")
                )
            ).one() == (1, 0)
    finally:
        await database.close_db()
