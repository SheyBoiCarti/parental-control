from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select


MAC = "AA:BB:CC:DD:EE:41"


class Controller:
    def __init__(self, samples):
        self.samples = iter(samples)

    async def read_bandwidth_counters(self):
        return next(self.samples)


def sample(sent, received, *, address="192.0.2.41", class_id=10):
    return {
        MAC: {
            "ip_address": address,
            "class_id": class_id,
            "bytes_sent": sent,
            "bytes_received": received,
        }
    }


@pytest.mark.asyncio
async def test_monitor_baselines_deltas_resets_and_address_reuse(tmp_path):
    from config import AppConfig
    from core.bandwidth_monitor import BandwidthMonitor
    from db import database
    from db.models import BandwidthLog, Device

    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            session.add(Device(mac_address=MAC, ip_address="192.0.2.41"))
        broadcasts = []

        async def broadcast(value):
            broadcasts.append(value)

        monitor = BandwidthMonitor(
            Controller([
                sample(100, 200),
                sample(150, 300),
                sample(20, 10),
                sample(30, 30),
                sample(500, 500, address="192.0.2.42"),
            ]),
            database.get_session,
            broadcast,
        )

        assert await monitor.poll_once() == 0
        assert await monitor.poll_once() == 1
        assert await monitor.poll_once() == 0
        assert await monitor.poll_once() == 1
        assert await monitor.poll_once() == 0

        async with database.get_session() as session:
            logs = list((await session.execute(
                select(BandwidthLog).order_by(BandwidthLog.id)
            )).scalars())
        assert [(row.bytes_sent, row.bytes_received) for row in logs] == [
            (50, 100),
            (10, 20),
        ]
        assert [(row["bytes_sent"], row["bytes_received"]) for row in broadcasts] == [
            (50, 100),
            (10, 20),
        ]
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_monitor_prunes_only_expired_access_and_bandwidth_logs(tmp_path):
    from config import AppConfig
    from core.bandwidth_monitor import BandwidthMonitor
    from db import database
    from db.models import AccessLog, BandwidthLog, Device

    now = datetime(2026, 9, 7, 12, 0, 0)
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            device = Device(mac_address=MAC)
            session.add(device)
            await session.flush()
            session.add_all([
                BandwidthLog(
                    device_id=device.id,
                    timestamp=now - timedelta(days=31),
                    bytes_sent=1,
                ),
                BandwidthLog(
                    device_id=device.id,
                    timestamp=now - timedelta(days=29),
                    bytes_sent=2,
                ),
                AccessLog(
                    device_id=device.id,
                    timestamp=now - timedelta(days=31),
                    domain="old.example",
                    action="allowed",
                ),
                AccessLog(
                    device_id=device.id,
                    timestamp=now - timedelta(days=29),
                    domain="new.example",
                    action="allowed",
                ),
            ])

        monitor = BandwidthMonitor(
            Controller([]),
            database.get_session,
            lambda value: None,
            retention_days=30,
            clock=lambda: now,
        )
        assert await monitor.prune_once() == 2

        async with database.get_session() as session:
            bandwidth = list((await session.execute(select(BandwidthLog))).scalars())
            access = list((await session.execute(select(AccessLog))).scalars())
        assert [row.bytes_sent for row in bandwidth] == [2]
        assert [row.domain for row in access] == ["new.example"]
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_monitor_stop_cancels_a_stalled_kernel_poll():
    from core.bandwidth_monitor import BandwidthMonitor

    started = asyncio.Event()
    cancelled = asyncio.Event()

    class StalledController:
        async def read_bandwidth_counters(self):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    monitor = BandwidthMonitor(
        StalledController(),
        None,
        lambda value: None,
    )
    await monitor.start()
    await asyncio.wait_for(started.wait(), timeout=0.2)

    with pytest.raises(RuntimeError, match="did not stop"):
        await monitor.stop(timeout=0.01)

    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_monitor_reports_poll_failure_and_keeps_running():
    from core.bandwidth_monitor import BandwidthMonitor

    recovered = asyncio.Event()

    class RecoveringController:
        def __init__(self):
            self.calls = 0

        async def read_bandwidth_counters(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary tc failure")
            recovered.set()
            return {}

    controller = RecoveringController()
    monitor = BandwidthMonitor(
        controller,
        None,
        lambda value: None,
        interval_seconds=0.01,
    )

    await monitor.start()
    await asyncio.wait_for(recovered.wait(), timeout=0.2)
    await monitor.stop()

    assert controller.calls >= 2
    assert monitor.stats()["poll_failures"] == 1
    assert monitor.stats()["prune_failures"] == 1


@pytest.mark.asyncio
async def test_failed_persistence_does_not_discard_uncommitted_counter_delta(tmp_path):
    from config import AppConfig
    from core.bandwidth_monitor import BandwidthMonitor
    from db import database
    from db.models import BandwidthLog, Device

    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            session.add(Device(mac_address=MAC))
        attempts = 0

        @asynccontextmanager
        async def sessions():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("database unavailable")
            async with database.get_session() as session:
                yield session

        monitor = BandwidthMonitor(
            Controller([sample(100, 100), sample(150, 160), sample(200, 220)]),
            sessions,
            lambda value: None,
        )
        assert await monitor.poll_once() == 0
        with pytest.raises(RuntimeError, match="database unavailable"):
            await monitor.poll_once()
        assert await monitor.poll_once() == 1

        async with database.get_session() as session:
            row = (await session.execute(select(BandwidthLog))).scalar_one()
        assert (row.bytes_sent, row.bytes_received) == (100, 120)
    finally:
        await database.close_db()
