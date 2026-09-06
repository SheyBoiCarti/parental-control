import asyncio
from dataclasses import FrozenInstanceError
import pytest


@pytest.mark.asyncio
async def test_worker_thread_delivery_is_batched_and_drained():
    from core.packet_events import AccessEvent, EventWorker
    batches = []
    async def sink(events):
        batches.append(events)
    worker = EventWorker(sink, capacity=4, batch_size=2, flush_seconds=0.02)
    await worker.start()
    event = AccessEvent("AA:BB:CC:DD:EE:01", "example.com", "allowed")
    with pytest.raises(FrozenInstanceError):
        event.domain = "changed"
    await asyncio.to_thread(worker.submit, event)
    await asyncio.to_thread(worker.submit, AccessEvent(event.mac, "second.example", "allowed"))
    await worker.stop()
    assert [e.domain for batch in batches for e in batch] == ["example.com", "second.example"]
    assert worker.stats()["persisted"] == 2


@pytest.mark.asyncio
async def test_queue_overflow_and_retry_preserve_identity():
    from core.packet_events import AccessEvent, EventWorker
    attempts = []
    async def sink(events):
        attempts.append([e.event_id for e in events])
        if len(attempts) == 1:
            raise RuntimeError("temporary database failure")
    worker = EventWorker(sink, capacity=1, batch_size=1, flush_seconds=0.01)
    await worker.start()
    assert worker.submit(AccessEvent("AA:BB:CC:DD:EE:01", "example.com", "allowed"))
    assert not worker.submit(AccessEvent("AA:BB:CC:DD:EE:01", "overflow.example", "allowed"))
    await worker.stop()
    assert attempts[0] == attempts[1]
    assert worker.stats()["lost"] == 1
    assert worker.stats()["persisted"] == 1


@pytest.mark.asyncio
async def test_database_retry_does_not_duplicate_events(tmp_path, monkeypatch):
    from core.packet_events import AccessEvent, persist_events
    from config import AppConfig
    from db import database
    from db.models import Device, DeviceRule, AccessLog
    from sqlalchemy import select
    from unittest.mock import AsyncMock
    broadcast = AsyncMock()
    monkeypatch.setattr("api.websocket.ws_manager.broadcast_access_log", broadcast)
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            session.add(Device(id=1, mac_address="AA:BB:CC:DD:EE:01"))
            session.add(DeviceRule(
                id=17,
                device_id=1,
                rule_type="block_domain",
                rule_value={"domain": "example.com"},
                canonical_value="example.com",
            ))
        event = AccessEvent(
            "AA:BB:CC:DD:EE:01",
            "example.com",
            "blocked",
            app_name="example-app",
            rule_id=17,
            protocol="tls_sni",
            reason="domain_rule",
        )
        await persist_events((event,))
        await persist_events((event,))
        async with database.get_session() as session:
            logs = list((await session.execute(select(AccessLog))).scalars())
            assert len(logs) == 1
        assert logs[0].event_id == event.event_id
        assert logs[0].timestamp == event.timestamp
        assert (logs[0].rule_id, logs[0].protocol, logs[0].reason) == (
            17,
            "tls_sni",
            "domain_rule",
        )
        assert broadcast.await_count == 1
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_passive_callbacks_deliver_from_thread_without_claiming_drop():
    from types import SimpleNamespace
    from config import AppConfig
    from main import ParentalControlApp
    from core.packet_events import EventWorker
    callbacks = {}
    received = []
    async def sink(events):
        received.extend(events)
    app = ParentalControlApp(AppConfig())
    app.state = SimpleNamespace(packet_analyzer=SimpleNamespace(
        add_dns_callback=lambda callback: callbacks.update(dns=callback),
        add_tls_callback=lambda callback: callbacks.update(tls=callback),
    ))
    app.event_worker = EventWorker(sink)
    await app.event_worker.start()
    app._setup_packet_callbacks()
    await asyncio.to_thread(callbacks["dns"], SimpleNamespace(src_mac="AA:BB:CC:DD:EE:01", domain="example.com"))
    await asyncio.to_thread(callbacks["tls"], SimpleNamespace(src_mac="AA:BB:CC:DD:EE:01", sni="example.com"))
    await app.event_worker.stop()
    assert len(received) == 2
    assert all(event.action == "allowed" for event in received)


@pytest.mark.asyncio
async def test_unknown_device_does_not_discard_known_device_events(tmp_path):
    from core.packet_events import AccessEvent, EventWorker, persist_events
    from config import AppConfig
    from db import database
    from db.models import Device, AccessLog
    from sqlalchemy import select
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            session.add(Device(mac_address="AA:BB:CC:DD:EE:01"))
        worker = EventWorker(persist_events)
        await worker.start()
        worker.submit(AccessEvent("AA:BB:CC:DD:EE:02", "unknown.example", "allowed"))
        worker.submit(AccessEvent("AA:BB:CC:DD:EE:01", "known.example", "allowed"))
        await worker.stop()
        async with database.get_session() as session:
            assert list((await session.execute(select(AccessLog.domain))).scalars()) == ["known.example"]
        assert worker.stats()["lost"] == 1
        assert worker.stats()["persisted"] == 1
    finally:
        await database.close_db()
