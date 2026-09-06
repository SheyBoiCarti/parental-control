from types import SimpleNamespace
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
        traffic_controller=component("traffic", "shutdown"),
        device_blocker=component("firewall", "shutdown"),
    )
    with pytest.raises(ExceptionGroup) as error:
        await app.stop_services()
    assert calls == ["scan", "arp", "capture", "traffic", "firewall", "database"]
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
        "state-reset",
        "intent-replayed",
        "interception-started",
        "observation-started",
    ]
