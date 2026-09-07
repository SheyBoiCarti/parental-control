from types import SimpleNamespace
import asyncio
import time
import pytest
from config import AppConfig
from main import ParentalControlApp


@pytest.mark.asyncio
async def test_shutdown_attempts_remaining_cleanup_and_database_after_failure(monkeypatch):
    calls = []
    def component(name, method, fail=False):
        async def cleanup():
            calls.append(name)
            if fail:
                raise RuntimeError(name + " failed")
        return SimpleNamespace(**{method: cleanup})
    async def close():
        calls.append("database")
    monkeypatch.setattr("db.database.close_db", close)
    app = ParentalControlApp(AppConfig())
    app.state = SimpleNamespace(
        device_manager=component("scan", "stop_periodic_scan", True),
        arp_spoofer=component("arp", "stop"),
        packet_analyzer=component("capture", "stop", True),
        reconciliation_worker=component("reconciliation", "stop"),
        bandwidth_monitor=component("accounting", "stop"),
        traffic_controller=component("traffic", "shutdown"),
        device_blocker=component("firewall", "shutdown"),
    )
    with pytest.raises(ExceptionGroup) as error:
        await app.stop_services()
    assert calls == [
        "scan", "arp", "capture", "reconciliation", "accounting",
        "traffic", "firewall", "database"
    ]
    assert len(error.value.exceptions) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("initial", [False, True])
async def test_forwarding_restores_original_value(monkeypatch, initial):
    from core import arp_spoofer
    state = {"enabled": initial}
    def enable():
        state["enabled"] = True
        return True
    def disable():
        state["enabled"] = False
        return True
    monkeypatch.setattr(arp_spoofer, "get_ip_forwarding_status", lambda: state["enabled"], raising=False)
    monkeypatch.setattr(arp_spoofer, "enable_ip_forwarding", enable)
    monkeypatch.setattr(arp_spoofer, "disable_ip_forwarding", disable)
    spoofer = arp_spoofer.ARPSpoofer("eth0", "192.0.2.1", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
    try:
        await spoofer.start()
        assert state["enabled"]
    finally:
        await spoofer.stop()
    assert state["enabled"] == initial


@pytest.mark.asyncio
async def test_enforcement_is_replayed_before_interception_starts():
    calls = []

    def async_step(name):
        async def step():
            calls.append(name)
        return step

    app = ParentalControlApp(AppConfig())
    app.state = SimpleNamespace(
        traffic_controller=SimpleNamespace(initialize=async_step("traffic-ready")),
        content_enforcer=SimpleNamespace(initialize=async_step("content-ready")),
        reconciler=SimpleNamespace(
            reset_runtime_state=async_step("state-reset"),
            reconcile_all=async_step("intent-replayed"),
        ),
        arp_spoofer=SimpleNamespace(start=async_step("interception-started")),
        packet_analyzer=SimpleNamespace(start=async_step("observation-started")),
    )

    await app._start_network_enforcement()

    assert calls == [
        "traffic-ready",
        "content-ready",
        "state-reset",
        "intent-replayed",
        "interception-started",
        "observation-started",
    ]


@pytest.mark.asyncio
async def test_shutdown_budget_cancels_stalled_cleanup_and_still_closes_database(
    monkeypatch,
):
    calls = []
    cancelled = asyncio.Event()

    async def stalled():
        calls.append("stalled")
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    async def close():
        calls.append("database")

    async def complete():
        calls.append("complete")

    monkeypatch.setattr("db.database.close_db", close)
    app = ParentalControlApp(AppConfig())
    app.state = SimpleNamespace(
        device_manager=SimpleNamespace(stop_periodic_scan=stalled),
        arp_spoofer=SimpleNamespace(stop=complete),
        packet_analyzer=SimpleNamespace(stop=complete),
        traffic_controller=SimpleNamespace(shutdown=complete),
        device_blocker=SimpleNamespace(shutdown=complete),
    )

    started = time.monotonic()
    with pytest.raises(ExceptionGroup, match="shutdown failed"):
        await app.stop_services(timeout=0.08)

    assert time.monotonic() - started < 0.2
    assert cancelled.is_set()
    assert calls[-1] == "database"
