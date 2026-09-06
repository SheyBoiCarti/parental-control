import json
from pathlib import Path
import sqlite3
import asyncio
import pytest
from sqlalchemy import select
from config import AppConfig
from db import database
from db.models import DeviceRule


@pytest.mark.asyncio
async def test_equivalent_legacy_rules_merge_without_losing_active_intent(tmp_path):
    with sqlite3.connect(tmp_path / "parental_control.db") as connection:
        connection.executescript((Path(__file__).parent / "fixtures/legacy.sql").read_text())
        connection.execute("INSERT INTO devices (id,mac_address) VALUES (1,'AA:BB:CC:DD:EE:01')")
        for id, domain, active in [(1, "*.Example.COM.", 0), (2, "*.example.com", 1)]:
            connection.execute("INSERT INTO device_rules (id,device_id,rule_type,rule_value,is_active) VALUES (?,1,'block_domain',?,?)", (id, json.dumps({"domain": domain}), active))
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            rules = list((await session.execute(select(DeviceRule))).scalars())
            assert len(rules) == 1
            assert rules[0].id == 1
            assert rules[0].is_active
            assert rules[0].rule_value == {"domain": "*.example.com"}
        await database.init_db()
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_concurrent_equivalent_requests_return_one_rule(tmp_path):
    from db.models import Device
    from db.rules import save_rule
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:01")
            session.add(device)
            await session.flush()
            device_id = device.id
        rules = await asyncio.gather(*[
            save_rule(device_id, "block_domain", {"domain": domain})
            for domain in ["*.Example.COM.", "*.example.com", "*.EXAMPLE.com"]
        ])
        assert len({rule.id for rule in rules}) == 1
        async with database.get_session() as session:
            assert len(list((await session.execute(select(DeviceRule))).scalars())) == 1
    finally:
        await database.close_db()
