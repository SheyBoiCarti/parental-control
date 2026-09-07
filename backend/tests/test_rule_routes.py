from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from api.routes import rules
from core.reconciler import EnforcementStatus, ReconcileResult


def result(state, component_state, error=None):
    timestamp = "2026-09-06T00:00:00Z"
    components = {
        name: EnforcementStatus(
            component_state if name in {"interception", "bandwidth"} else "inactive",
            error if name in {"interception", "bandwidth"} else None,
            timestamp,
        )
        for name in ("interception", "blocking", "content", "bandwidth")
    }
    return ReconcileResult(state, components)


def saved_rule():
    values = {
        "id": 4,
        "device_id": 9,
        "rule_type": "bandwidth",
        "rule_value": {"download_kbps": 2000, "upload_kbps": 500},
        "is_active": True,
        "created_at": "2026-09-06T00:00:00",
        "validation_error": None,
    }
    return SimpleNamespace(**values, to_dict=lambda: values)


@pytest.mark.asyncio
async def test_offline_bandwidth_intent_returns_202_pending(monkeypatch):
    reconcile = AsyncMock(return_value=result("pending", "pending"))
    monkeypatch.setattr(rules, "_app_state", SimpleNamespace(reconciler=SimpleNamespace(reconcile=reconcile)))
    monkeypatch.setattr(
        rules,
        "get_device_by_mac",
        AsyncMock(return_value=SimpleNamespace(id=9, ip_address=None)),
    )
    monkeypatch.setattr(rules, "save_rule", AsyncMock(return_value=saved_rule()))
    monkeypatch.setattr(rules.ws_manager, "broadcast_rule_update", AsyncMock())
    response = Response()

    returned = await rules.create_bandwidth_rule(
        "AA:BB:CC:DD:EE:09",
        rules.BandwidthRuleRequest(download_kbps=2000, upload_kbps=500),
        response=response,
        user="admin",
    )

    assert response.status_code == 202
    assert returned.enforcement.state == "pending"
    reconcile.assert_awaited_once_with("AA:BB:CC:DD:EE:09")


@pytest.mark.asyncio
async def test_bandwidth_apply_failure_returns_stable_503_error(monkeypatch):
    failure = result("error", "error", "Bandwidth application failed")
    monkeypatch.setattr(
        rules,
        "_app_state",
        SimpleNamespace(
            arp_spoofer=SimpleNamespace(validate_target=lambda ip, mac: None),
            reconciler=SimpleNamespace(reconcile=AsyncMock(return_value=failure)),
        ),
    )
    monkeypatch.setattr(
        rules,
        "get_device_by_mac",
        AsyncMock(return_value=SimpleNamespace(id=9, ip_address="192.0.2.9")),
    )
    monkeypatch.setattr(rules, "save_rule", AsyncMock(return_value=saved_rule()))

    with pytest.raises(HTTPException) as raised:
        await rules.create_bandwidth_rule(
            "AA:BB:CC:DD:EE:09",
            rules.BandwidthRuleRequest(download_kbps=2000, upload_kbps=500),
            response=Response(),
            user="admin",
        )

    assert raised.value.status_code == 503
    assert raised.value.detail["code"] == "ENFORCEMENT_APPLY_FAILED"
    assert raised.value.detail["enforcement"]["state"] == "error"


@pytest.mark.asyncio
async def test_protected_target_rule_is_rejected_before_intent_is_saved(monkeypatch):
    def reject(ip_address, mac):
        raise ValueError("Gateway and appliance cannot be interception targets")

    save = AsyncMock()
    monkeypatch.setattr(
        rules,
        "_app_state",
        SimpleNamespace(
            arp_spoofer=SimpleNamespace(validate_target=reject),
            reconciler=SimpleNamespace(reconcile=AsyncMock()),
        ),
    )
    monkeypatch.setattr(
        rules,
        "get_device_by_mac",
        AsyncMock(return_value=SimpleNamespace(id=9, ip_address="192.0.2.1")),
    )
    monkeypatch.setattr(rules, "save_rule", save)

    with pytest.raises(HTTPException) as raised:
        await rules.create_bandwidth_rule(
            "AA:BB:CC:DD:EE:01",
            rules.BandwidthRuleRequest(download_kbps=2000, upload_kbps=500),
            response=Response(),
            user="admin",
        )

    assert raised.value.status_code == 422
    save.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_rule_removal_restores_intent_and_avoids_deleted_broadcast(
    tmp_path, monkeypatch
):
    from config import AppConfig
    from db import database
    from db.models import DeviceRule, Device
    from db.rules import save_rule as persist_rule
    from sqlalchemy import select

    database.configure_database(AppConfig(data_dir=tmp_path))
    try:
        await database.init_db()
        async with database.get_session() as session:
            device = Device(mac_address="AA:BB:CC:DD:EE:19")
            session.add(device)
            await session.flush()
            device_id = device.id
        saved = await persist_rule(
            device_id,
            "bandwidth",
            {"download_kbps": 2000, "upload_kbps": 500},
        )
        failure = result("error", "error", "Bandwidth removal failed")
        broadcast = AsyncMock()
        monkeypatch.setattr(
            rules,
            "_app_state",
            SimpleNamespace(
                reconciler=SimpleNamespace(
                    reconcile=AsyncMock(return_value=failure),
                ),
                content_blocker=SimpleNamespace(_load_device_rules=AsyncMock()),
            ),
        )
        monkeypatch.setattr(rules.ws_manager, "broadcast_rule_update", broadcast)

        with pytest.raises(HTTPException) as raised:
            await rules.delete_rule(
                "AA:BB:CC:DD:EE:19",
                saved.id,
                response=Response(),
                user="admin",
            )

        assert raised.value.status_code == 503
        async with database.get_session() as session:
            restored = list((await session.execute(select(DeviceRule))).scalars())
        assert len(restored) == 1
        assert restored[0].rule_value == {
            "download_kbps": 2000,
            "upload_kbps": 500,
        }
        broadcast.assert_not_awaited()
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_available_apps_return_stable_identifier_and_catalog_display_name(
    monkeypatch,
):
    blocker = SimpleNamespace(
        get_available_apps=lambda: {"example_chat": ["*.example.test"]},
        get_available_app_records=lambda: [
            {
                "name": "example_chat",
                "display_name": "Example Chat",
                "domains": ["*.example.test"],
            }
        ],
    )
    monkeypatch.setattr(
        rules,
        "_app_state",
        SimpleNamespace(content_blocker=blocker),
    )

    response = await rules.list_available_apps(user="admin")

    assert response == {"apps": [{
        "name": "example_chat",
        "display_name": "Example Chat",
        "domains": ["*.example.test"],
    }]}
