"""Temporary, loopback-only backend fixture for Playwright acceptance tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import sys
import tempfile

import uvicorn
from sqlalchemy import select

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.app import create_app
from api.auth import hash_password
from api.routes import devices, rules, settings, stats
from config import AppConfig
from core.auth_service import AuthService
from core.content_blocker import ContentBlocker
from core.reconciler import EnforcementReconciler
from db.database import configure_database, get_session, init_db
from db.models import Device
from db.rules import save_rule
from utils.mac_utils import normalize_mac


class FakeDeviceManager:
    """Database-backed device state with no discovery or network operations."""

    interface = "e2e0"
    local_mac = "02:00:00:00:00:01"
    local_ip = "192.0.2.2"
    gateway_ip = "192.0.2.1"
    gateway_mac = "02:00:00:00:00:02"
    subnet = "192.0.2.0/24"

    async def get_all_devices(self):
        async with get_session() as session:
            return list((await session.execute(select(Device).order_by(Device.id))).scalars())

    async def get_device_by_mac(self, mac: str):
        async with get_session() as session:
            return (await session.execute(
                select(Device).where(Device.mac_address == normalize_mac(mac))
            )).scalar_one_or_none()

    async def update_device(self, mac: str, *, friendly_name=None, is_monitored=None, is_blocked=None):
        async with get_session() as session:
            device = (await session.execute(
                select(Device).where(Device.mac_address == normalize_mac(mac))
            )).scalar_one_or_none()
            if device is None:
                return None
            if friendly_name is not None:
                device.friendly_name = friendly_name
            if is_monitored is not None:
                device.is_monitored = is_monitored
            if is_blocked is not None:
                device.is_blocked = is_blocked
            await session.flush()
            await session.refresh(device)
            return device

    async def scan_network(self):
        return []

    async def update_devices_from_scan(self, _discovered):
        return await self.get_all_devices()


class FakeArpAdapter:
    _running = False
    active_targets: dict[str, str] = {}

    def validate_target(self, _ip_address: str, _mac: str) -> None:
        return None

    def add_target(self, _ip_address: str, _mac: str) -> bool:
        return True

    def remove_target(self, _mac: str) -> bool:
        return True


class FakeBlockAdapter:
    def __init__(self):
        self.blocked: set[str] = set()

    async def block_device(self, mac: str) -> bool:
        self.blocked.add(normalize_mac(mac))
        return True

    async def unblock_device(self, mac: str) -> bool:
        self.blocked.discard(normalize_mac(mac))
        return True

    def is_blocked(self, mac: str) -> bool:
        return normalize_mac(mac) in self.blocked


class FakeTrafficAdapter:
    async def set_bandwidth_limit(self, _mac: str, _download: int, _upload: int, *, ip_address: str) -> bool:
        return True

    async def remove_bandwidth_limit(self, _mac: str) -> bool:
        return True


class FakeContentAdapter:
    """Fails one deterministic test rule after the real route persists intent."""

    async def apply_device(self, _mac: str, _ip_address: str, rules_to_apply) -> bool:
        return not any(
            rule.rule_type == "block_domain" and rule.rule_value.get("domain") == "reject.example"
            for rule in rules_to_apply
        )

    async def remove_device(self, _mac: str) -> bool:
        return True


class FakePacketAnalyzer:
    _running = False

    @staticmethod
    def get_stats():
        return {"dns_queries": 0, "tls_connections": 0}


@dataclass
class TestState:
    device_manager: FakeDeviceManager
    arp_spoofer: FakeArpAdapter
    packet_analyzer: FakePacketAnalyzer
    traffic_controller: FakeTrafficAdapter
    content_blocker: ContentBlocker
    device_blocker: FakeBlockAdapter
    reconciler: EnforcementReconciler


async def seed() -> None:
    async with get_session() as session:
        session.add_all([
            Device(
                mac_address="02:00:00:00:00:10", ip_address="192.0.2.10",
                hostname="desktop", friendly_name="Desktop", vendor="Test Vendor", is_online=True,
            ),
            Device(
                mac_address="02:00:00:00:00:20", ip_address=None,
                hostname="tablet", friendly_name="Offline Tablet", vendor="Test Vendor",
                is_monitored=True, is_online=False,
            ),
        ])


async def build_app(data_dir: Path):
    password = os.environ.get("PC_E2E_PASSWORD")
    password_file = os.environ.get("PC_E2E_PASSWORD_FILE")
    if not password or not password_file:
        raise RuntimeError("PC_E2E_PASSWORD is required for the Playwright fixture")
    credential_fixture = Path(password_file)
    credential_fixture.parent.mkdir(parents=True, exist_ok=True)
    credential_fixture.write_text(password, encoding="utf-8")
    config = AppConfig(
        data_dir=data_dir,
        static_dir=PROJECT_DIR / "frontend" / "dist",
        api_host="127.0.0.1",
        api_port=4173,
        auth_username="e2e-admin",
        auth_password_hash=hash_password(password),
        allowed_origins=("http://127.0.0.1:4173",),
        allow_insecure_development=True,
    )
    configure_database(config)
    await init_db()
    await seed()
    manager = FakeDeviceManager()
    desktop = await manager.get_device_by_mac("02:00:00:00:00:10")
    assert desktop is not None
    await save_rule(desktop.id, "bandwidth", {"download_kbps": 2_000, "upload_kbps": 1_000})
    content_blocker = ContentBlocker()
    await content_blocker.initialize()
    arp = FakeArpAdapter()
    blocker = FakeBlockAdapter()
    traffic = FakeTrafficAdapter()
    reconciler = EnforcementReconciler(get_session, arp, blocker, traffic, FakeContentAdapter())
    for device in await manager.get_all_devices():
        await reconciler.reconcile(device.mac_address)
    state = TestState(manager, arp, FakePacketAnalyzer(), traffic, content_blocker, blocker, reconciler)
    devices.set_app_state(state)
    rules.set_app_state(state)
    settings.set_app_state(state)
    stats.set_app_state(state)
    auth_service = AuthService(get_session)
    await auth_service.ensure_configured()
    return create_app(config, auth_service=auth_service)


async def serve() -> None:
    password_file = os.environ.get("PC_E2E_PASSWORD_FILE")
    try:
        with tempfile.TemporaryDirectory(prefix="parental-control-e2e-") as temporary:
            app = await build_app(Path(temporary))
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=4173, log_level="warning"))
            await server.serve()
    finally:
        if password_file:
            Path(password_file).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(serve())
