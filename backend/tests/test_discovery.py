from datetime import datetime, timedelta
import asyncio
import threading
from types import SimpleNamespace

import pytest

from config import AppConfig
from core.device_manager import DeviceManager, DiscoveredDevice
from db import database
from db.models import Device


@pytest.mark.asyncio
async def test_scan_result_is_complete_persisted_snapshot(tmp_path):
    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            session.add_all([
                Device(mac_address="AA:BB:CC:DD:EE:01", last_seen=datetime.utcnow() - timedelta(minutes=6), is_online=True, friendly_name="Saved name", is_blocked=True),
                Device(mac_address="AA:BB:CC:DD:EE:02", last_seen=datetime.utcnow(), is_online=True),
            ])
            await session.commit()
        manager = DeviceManager("eth0")
        snapshot = await manager.update_devices_from_scan([
            DiscoveredDevice("AA:BB:CC:DD:EE:03", "192.0.2.3")
        ])
        by_mac = {d.mac_address: d for d in snapshot}
        assert len(by_mac) == 3
        old = by_mac["AA:BB:CC:DD:EE:01"]
        assert not old.is_online
        assert old.friendly_name == "Saved name" and old.is_blocked
        assert by_mac["AA:BB:CC:DD:EE:02"].is_online
        assert by_mac["AA:BB:CC:DD:EE:03"].is_online
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_failed_scan_raises_instead_of_returning_empty_success(monkeypatch):
    def failed(*args, **kwargs):
        raise OSError("capture unavailable")
    monkeypatch.setattr("core.device_manager.srp", failed)
    manager = DeviceManager("eth0", network_subnet="192.0.2.0/24")
    with pytest.raises(RuntimeError, match="Network scan failed"):
        await manager.scan_network()


@pytest.mark.asyncio
async def test_scan_runs_off_loop_and_excludes_gateway_and_appliance(monkeypatch):
    loop_thread = threading.get_ident()
    def scan(*args, **kwargs):
        assert threading.get_ident() != loop_thread
        return ([(None, SimpleNamespace(hwsrc=mac, psrc=ip)) for mac, ip in [
            ("AA:BB:CC:DD:EE:01", "192.0.2.1"),
            ("AA:BB:CC:DD:EE:02", "192.0.2.2"),
            ("AA:BB:CC:DD:EE:03", "192.0.2.3"),
        ]], [])
    monkeypatch.setattr("core.device_manager.srp", scan)
    monkeypatch.setattr("core.device_manager.get_hostname_from_ip", lambda ip: None)
    manager = DeviceManager("eth0", gateway_ip="192.0.2.1", network_subnet="192.0.2.0/24")
    manager.local_mac = "AA:BB:CC:DD:EE:02"
    devices = await asyncio.wait_for(manager.scan_network(), 2)
    assert [d.ip_address for d in devices] == ["192.0.2.3"]


@pytest.mark.asyncio
async def test_scan_api_failure_does_not_write_or_broadcast(monkeypatch):
    from unittest.mock import AsyncMock
    from fastapi import HTTPException
    from api.routes import devices
    manager = SimpleNamespace(scan_network=AsyncMock(side_effect=RuntimeError("failed")),
                              update_devices_from_scan=AsyncMock())
    monkeypatch.setattr(devices, "_app_state", SimpleNamespace(device_manager=manager))
    broadcast = AsyncMock()
    monkeypatch.setattr(devices.ws_manager, "broadcast_devices_list", broadcast)
    with pytest.raises(HTTPException) as error:
        await devices.trigger_scan(user="admin")
    assert error.value.status_code == 503
    manager.update_devices_from_scan.assert_not_awaited()
    broadcast.assert_not_awaited()
