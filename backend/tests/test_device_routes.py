from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from api.routes import devices
from core.reconciler import EnforcementStatus, ReconcileResult


def device(mac="AA:BB:CC:DD:EE:10", *, monitored=False, blocked=False, ip=None):
    values = {
        "id": 10,
        "mac_address": mac,
        "ip_address": ip,
        "hostname": None,
        "vendor": None,
        "friendly_name": "Child device",
        "is_monitored": monitored,
        "is_blocked": blocked,
        "first_seen": "2026-09-06T00:00:00",
        "last_seen": "2026-09-06T00:00:00",
        "is_online": ip is not None,
    }
    return SimpleNamespace(**values, to_dict=lambda: values)


def result(state, interception, blocking="inactive"):
    timestamp = "2026-09-06T00:00:00Z"
    components = {
        "interception": EnforcementStatus(interception, None, timestamp),
        "blocking": EnforcementStatus(
            blocking,
            "Device block application failed" if blocking == "error" else None,
            timestamp,
        ),
        "content": EnforcementStatus("inactive", None, timestamp),
        "bandwidth": EnforcementStatus("inactive", None, timestamp),
    }
    return ReconcileResult(state, components)


@pytest.mark.asyncio
async def test_offline_monitoring_update_returns_pending_intent(monkeypatch):
    saved = device(monitored=True)
    manager = SimpleNamespace(
        get_device_by_mac=AsyncMock(return_value=device()),
        update_device=AsyncMock(return_value=saved),
    )
    pending = result("pending", "pending")
    state = SimpleNamespace(
        device_manager=manager,
        arp_spoofer=SimpleNamespace(validate_target=lambda ip, mac: None),
        reconciler=SimpleNamespace(reconcile=AsyncMock(return_value=pending)),
    )
    monkeypatch.setattr(devices, "_app_state", state)
    monkeypatch.setattr(devices.ws_manager, "broadcast_device_update", AsyncMock())
    response = Response()

    returned = await devices.update_device(
        saved.mac_address,
        devices.DeviceUpdateRequest(is_monitored=True),
        response=response,
        user="admin",
    )

    assert response.status_code == 202
    assert returned.is_monitored is True
    assert returned.enforcement.state == "pending"


@pytest.mark.asyncio
async def test_failed_block_update_returns_503_with_saved_desired_state(monkeypatch):
    saved = device(blocked=True, ip="192.0.2.10")
    manager = SimpleNamespace(
        get_device_by_mac=AsyncMock(return_value=device(ip="192.0.2.10")),
        update_device=AsyncMock(return_value=saved),
    )
    failure = result("error", "error", "error")
    state = SimpleNamespace(
        device_manager=manager,
        arp_spoofer=SimpleNamespace(validate_target=lambda ip, mac: None),
        reconciler=SimpleNamespace(reconcile=AsyncMock(return_value=failure)),
    )
    monkeypatch.setattr(devices, "_app_state", state)
    monkeypatch.setattr(devices.ws_manager, "broadcast_device_update", AsyncMock())

    with pytest.raises(HTTPException) as raised:
        await devices.update_device(
            saved.mac_address,
            devices.DeviceUpdateRequest(is_blocked=True),
            response=Response(),
            user="admin",
        )

    assert raised.value.status_code == 503
    assert raised.value.detail["code"] == "ENFORCEMENT_APPLY_FAILED"
    manager.update_device.assert_awaited_once()
    assert manager.update_device.await_args.kwargs["is_blocked"] is True
