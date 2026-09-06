from contextlib import asynccontextmanager
import asyncio

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from core.reconciler import EnforcementReconciler
from db.models import Base, Device, DeviceEnforcement, DeviceRule


class FakeARP:
    def __init__(self):
        self.targets = {}

    def validate_target(self, ip, mac):
        return None

    def add_target(self, ip, mac):
        self.targets[mac.upper()] = ip
        return True

    async def update_target_ip(self, mac, ip):
        self.targets[mac.upper()] = ip

    def remove_target(self, mac):
        return self.targets.pop(mac.upper(), None) is not None

    @property
    def active_targets(self):
        return set(self.targets)


class FakeBlocker:
    def __init__(self):
        self.blocked = set()

    async def block_device(self, mac):
        self.blocked.add(mac.upper())
        return True

    async def unblock_device(self, mac):
        self.blocked.discard(mac.upper())
        return True

    def is_blocked(self, mac):
        return mac.upper() in self.blocked


class FakeTraffic:
    def __init__(self, succeeds=True):
        self.succeeds = succeeds
        self.limits = {}

    async def set_bandwidth_limit(self, mac, download, upload, *, ip_address):
        if not self.succeeds:
            return False
        self.limits[mac.upper()] = (download, upload, ip_address)
        return True

    async def remove_bandwidth_limit(self, mac):
        self.limits.pop(mac.upper(), None)
        return True


@pytest_asyncio.fixture
async def reconciliation_db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'reconcile.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def sessions():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except BaseException:
                await session.rollback()
                raise

    try:
        yield sessions
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_unknown_address_persists_pending_instead_of_claiming_protection(reconciliation_db):
    async with reconciliation_db() as session:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:01",
            ip_address=None,
            is_online=False,
            is_monitored=True,
        )
        session.add(device)

    reconciler = EnforcementReconciler(
        reconciliation_db, FakeARP(), FakeBlocker(), FakeTraffic()
    )
    result = await reconciler.reconcile("AA:BB:CC:DD:EE:01")

    assert result.components["interception"].state == "pending"
    assert result.components["interception"].last_error is None
    async with reconciliation_db() as session:
        record = (
            await session.execute(
                select(DeviceEnforcement).where(
                    DeviceEnforcement.device_id == device.id,
                    DeviceEnforcement.component == "interception",
                )
            )
        ).scalar_one()
        assert record.state == "pending"


@pytest.mark.asyncio
async def test_bandwidth_failure_is_persisted_and_returned_as_error(reconciliation_db):
    async with reconciliation_db() as session:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:02",
            ip_address="192.0.2.22",
            is_online=True,
        )
        session.add(device)
        await session.flush()
        session.add(
            DeviceRule(
                device_id=device.id,
                rule_type="bandwidth",
                rule_value={"download_kbps": 2000, "upload_kbps": 500},
                canonical_value="bandwidth",
                is_active=True,
            )
        )

    reconciler = EnforcementReconciler(
        reconciliation_db, FakeARP(), FakeBlocker(), FakeTraffic(succeeds=False)
    )
    result = await reconciler.reconcile("aa:bb:cc:dd:ee:02")

    assert result.components["bandwidth"].state == "error"
    assert result.components["bandwidth"].last_error == "Bandwidth application failed"
    assert result.components["interception"].state == "error"
    assert result.state == "error"


@pytest.mark.asyncio
async def test_real_arp_public_interface_can_apply_interception(reconciliation_db):
    class PublicARP:
        def __init__(self):
            self._active = set()

        @property
        def active_targets(self):
            return set(self._active)

        def validate_target(self, ip, mac):
            return None

        def add_target(self, ip, mac):
            self._active.add(mac)
            return True

        async def update_target_ip(self, mac, ip):
            return None

        def remove_target(self, mac):
            self._active.discard(mac)
            return True

    async with reconciliation_db() as session:
        session.add(Device(
            mac_address="AA:BB:CC:DD:EE:03",
            ip_address="192.0.2.23",
            is_online=True,
            is_monitored=True,
        ))

    result = await EnforcementReconciler(
        reconciliation_db, PublicARP(), FakeBlocker(), FakeTraffic()
    ).reconcile("AA:BB:CC:DD:EE:03")

    assert result.components["interception"].state == "applied"


@pytest.mark.asyncio
async def test_same_device_reconciliation_is_serialized(reconciliation_db):
    class SlowTraffic(FakeTraffic):
        def __init__(self):
            super().__init__()
            self.active = 0
            self.max_active = 0

        async def set_bandwidth_limit(self, mac, download, upload, *, ip_address):
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            await asyncio.sleep(0.01)
            result = await super().set_bandwidth_limit(
                mac, download, upload, ip_address=ip_address
            )
            self.active -= 1
            return result

    async with reconciliation_db() as session:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:04",
            ip_address="192.0.2.24",
            is_online=True,
        )
        session.add(device)
        await session.flush()
        session.add(DeviceRule(
            device_id=device.id,
            rule_type="bandwidth",
            rule_value={"download_kbps": 2000, "upload_kbps": 500},
            canonical_value="bandwidth",
            is_active=True,
        ))

    traffic = SlowTraffic()
    reconciler = EnforcementReconciler(
        reconciliation_db, FakeARP(), FakeBlocker(), traffic
    )
    await asyncio.gather(
        reconciler.reconcile("AA:BB:CC:DD:EE:04"),
        reconciler.reconcile("AA:BB:CC:DD:EE:04"),
    )

    assert traffic.max_active == 1


@pytest.mark.asyncio
async def test_startup_reset_does_not_preserve_stale_applied_truth(reconciliation_db):
    async with reconciliation_db() as session:
        device = Device(mac_address="AA:BB:CC:DD:EE:05", is_monitored=True)
        session.add(device)
        await session.flush()
        session.add(DeviceEnforcement(
            device_id=device.id,
            component="interception",
            state="applied",
        ))

    reconciler = EnforcementReconciler(
        reconciliation_db, FakeARP(), FakeBlocker(), FakeTraffic()
    )
    await reconciler.reset_runtime_state()

    loaded = await reconciler.get_status("AA:BB:CC:DD:EE:05")
    assert loaded.components["interception"].state == "pending"

    async with reconciliation_db() as session:
        record = (
            await session.execute(select(DeviceEnforcement))
        ).scalar_one()
        assert record.state == "pending"
        assert record.last_error is None


@pytest.mark.asyncio
async def test_reconcile_all_replays_every_persisted_device(reconciliation_db):
    async with reconciliation_db() as session:
        session.add_all([
            Device(
                mac_address="AA:BB:CC:DD:EE:06",
                ip_address="192.0.2.26",
                is_monitored=True,
            ),
            Device(
                mac_address="AA:BB:CC:DD:EE:07",
                ip_address=None,
                is_blocked=True,
            ),
        ])

    arp = FakeARP()
    results = await EnforcementReconciler(
        reconciliation_db, arp, FakeBlocker(), FakeTraffic()
    ).reconcile_all()

    assert set(results) == {"AA:BB:CC:DD:EE:06", "AA:BB:CC:DD:EE:07"}
    assert results["AA:BB:CC:DD:EE:06"].state == "applied"
    assert results["AA:BB:CC:DD:EE:07"].state == "pending"
    assert arp.active_targets == {"AA:BB:CC:DD:EE:06"}


@pytest.mark.asyncio
async def test_full_block_suspends_and_then_restores_saved_bandwidth(reconciliation_db):
    mac = "AA:BB:CC:DD:EE:08"
    async with reconciliation_db() as session:
        device = Device(mac_address=mac, ip_address="192.0.2.28", is_online=True)
        session.add(device)
        await session.flush()
        session.add(DeviceRule(
            device_id=device.id,
            rule_type="bandwidth",
            rule_value={"download_kbps": 2000, "upload_kbps": 500},
            canonical_value="bandwidth",
            is_active=True,
        ))

    traffic = FakeTraffic()
    blocker = FakeBlocker()
    reconciler = EnforcementReconciler(reconciliation_db, FakeARP(), blocker, traffic)
    assert (await reconciler.reconcile(mac)).state == "applied"
    assert mac in traffic.limits

    async with reconciliation_db() as session:
        saved = (
            await session.execute(select(Device).where(Device.mac_address == mac))
        ).scalar_one()
        saved.is_blocked = True
    blocked = await reconciler.reconcile(mac)
    assert blocked.components["blocking"].state == "applied"
    assert blocked.components["bandwidth"].state == "applied"
    assert mac not in traffic.limits
    assert mac in blocker.blocked

    async with reconciliation_db() as session:
        saved = (
            await session.execute(select(Device).where(Device.mac_address == mac))
        ).scalar_one()
        saved.is_blocked = False
    unblocked = await reconciler.reconcile(mac)
    assert unblocked.components["bandwidth"].state == "applied"
    assert traffic.limits[mac] == (2000, 500, "192.0.2.28")
