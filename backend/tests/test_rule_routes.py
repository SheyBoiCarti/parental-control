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
        SimpleNamespace(reconciler=SimpleNamespace(reconcile=AsyncMock(return_value=failure))),
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
