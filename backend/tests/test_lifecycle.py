from types import SimpleNamespace
import asyncio
import time
import pytest
from config import AppConfig
from main import ParentalControlApp


@pytest.mark.asyncio
async def test_start_failure_rolls_back_only_acquired_services_in_reverse_order(monkeypatch):
    """A failure starting a later worker must not leave earlier services running."""
    calls = []

    class Service:
        def __init__(self, name):
            self.name = name

        async def start(self):
            calls.append(f"{self.name}:start")

        async def stop(self):
            calls.append(f"{self.name}:stop")

        async def initialize(self):
            calls.append(f"{self.name}:initialize")

        async def shutdown(self):
            calls.append(f"{self.name}:shutdown")

    class EventWorker(Service):
        def __init__(self, *args, **kwargs):
            super().__init__("events")

    class FailingReconciliationWorker(Service):
        def __init__(self, *args, **kwargs):
            super().__init__("reconciliation")

        async def start(self):
            calls.append("reconciliation:start")
            raise RuntimeError("reconciliation failed")

    from core import packet_events, reconciliation_worker

    monkeypatch.setattr(packet_events, "EventWorker", EventWorker)
    monkeypatch.setattr(reconciliation_worker, "ReconciliationWorker", FailingReconciliationWorker)

    app = ParentalControlApp(AppConfig())
    app.state = SimpleNamespace(
        device_manager=SimpleNamespace(add_online_callback=lambda callback: calls.append("scan:registered")),
        traffic_controller=Service("traffic"),
        content_enforcer=Service("content"),
        reconciler=SimpleNamespace(
            reset_runtime_state=Service("state").initialize,
            reconcile_all=Service("intent").initialize,
        ),
        arp_spoofer=Service("arp"),
        packet_analyzer=Service("capture"),
    )

    with pytest.raises(RuntimeError, match="reconciliation failed"):
        await app.start_services()

    assert calls == [
        "events:start",
        "scan:registered",
        "traffic:initialize",
        "content:initialize",
        "state:initialize",
        "intent:initialize",
        "arp:start",
        "capture:start",
        "reconciliation:start",
        "capture:stop",
        "arp:stop",
        "content:shutdown",
        "traffic:shutdown",
        "events:stop",
    ]


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
        "scan", "accounting", "reconciliation", "capture", "arp",
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
        traffic_controller=SimpleNamespace(
            initialize=async_step("traffic-ready"), shutdown=async_step("traffic-stopped")
        ),
        content_enforcer=SimpleNamespace(
            initialize=async_step("content-ready"), shutdown=async_step("content-stopped")
        ),
        reconciler=SimpleNamespace(
            reset_runtime_state=async_step("state-reset"),
            reconcile_all=async_step("intent-replayed"),
        ),
        arp_spoofer=SimpleNamespace(
            start=async_step("interception-started"), stop=async_step("interception-stopped")
        ),
        packet_analyzer=SimpleNamespace(
            start=async_step("observation-started"), stop=async_step("observation-stopped")
        ),
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


@pytest.mark.asyncio
async def test_shutdown_does_not_wait_for_cleanup_that_suppresses_cancellation():
    calls = []
    release = asyncio.Event()
    cancellation_seen = asyncio.Event()

    async def cancellation_resistant_cleanup():
        calls.append("stalled")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_seen.set()
            await release.wait()

    async def close_database():
        calls.append("database")

    app = ParentalControlApp(AppConfig())
    app._register_cleanup("database", close_database)
    app._register_cleanup("stalled", cancellation_resistant_cleanup)

    shutdown = asyncio.create_task(app.stop_services(timeout=0.02))
    while calls != ["stalled"]:
        await asyncio.sleep(0)
    await asyncio.sleep(0.03)

    try:
        assert shutdown.done()
        assert cancellation_seen.is_set()
        assert calls == ["stalled", "database"]
        assert app._cleanup_stack[-1][0] == "stalled"
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(shutdown, return_exceptions=True), timeout=0.1)

    with pytest.raises(ExceptionGroup, match="shutdown failed"):
        await shutdown
    pending = app._cleanup_tasks[app._cleanup_stack[-1]]
    await asyncio.wait_for(asyncio.shield(pending), timeout=0.1)
    await app.stop_services(timeout=0.1)
    assert not app._cleanup_stack


@pytest.mark.asyncio
async def test_run_preserves_startup_error_when_cleanup_fails(monkeypatch):
    app = ParentalControlApp(AppConfig())

    async def failed_cleanup():
        raise RuntimeError("cleanup failed")

    async def initialize_auth():
        app._register_cleanup("broken", failed_cleanup)

    async def initialize():
        raise RuntimeError("startup failed")

    monkeypatch.setattr(app, "initialize_auth", initialize_auth)
    monkeypatch.setattr(app, "initialize", initialize)
    monkeypatch.setattr("main.os.geteuid", lambda: 0, raising=False)

    with pytest.raises(RuntimeError, match="startup failed"):
        await app.run()


@pytest.mark.asyncio
async def test_configure_database_failure_does_not_close_unacquired_database(monkeypatch):
    calls = []

    def configure_database(config):
        raise RuntimeError("configuration failed")

    async def close_database():
        calls.append("database")

    monkeypatch.setattr("db.database.configure_database", configure_database)
    monkeypatch.setattr("db.database.close_db", close_database)

    app = ParentalControlApp(AppConfig())
    with pytest.raises(RuntimeError, match="configuration failed"):
        await app.initialize_auth()

    assert calls == []


@pytest.mark.asyncio
async def test_run_does_not_close_global_database_when_configuration_fails(monkeypatch):
    calls = []

    def configure_database(config):
        raise RuntimeError("configuration failed")

    async def close_database():
        calls.append("database")

    monkeypatch.setattr("db.database.configure_database", configure_database)
    monkeypatch.setattr("db.database.close_db", close_database)

    app = ParentalControlApp(AppConfig())
    with pytest.raises(RuntimeError, match="configuration failed"):
        await app.run()

    assert calls == []


@pytest.mark.asyncio
async def test_database_initialization_failure_closes_owned_database(monkeypatch):
    calls = []

    def configure_database(config):
        calls.append("configured")

    async def init_db():
        raise RuntimeError("migration failed")

    async def close_database():
        calls.append("closed")

    monkeypatch.setattr("db.database.configure_database", configure_database)
    monkeypatch.setattr("db.database.init_db", init_db)
    monkeypatch.setattr("db.database.close_db", close_database)

    app = ParentalControlApp(AppConfig())
    with pytest.raises(RuntimeError, match="migration failed"):
        await app.initialize_auth()

    assert calls == ["configured", "closed"]


def _install_returning_server_runtime(app, monkeypatch, calls):
    workers = []
    cycle = 0

    class Worker:
        def __init__(self, number):
            self.number = number

        async def start(self):
            calls.append(f"worker:{self.number}:start")

        async def stop(self):
            calls.append(f"worker:{self.number}:stop")

    class ReturningServer:
        def __init__(self, config):
            self.config = config

        async def serve(self):
            calls.append("server:return")

    async def initialize_auth():
        nonlocal cycle
        cycle += 1
        number = cycle
        calls.append(f"database:{number}:open")

        async def close_database():
            calls.append(f"database:{number}:close")

        app._register_cleanup("database", close_database)

    async def initialize():
        calls.append(f"initialize:{cycle}")

    async def start_services():
        worker = Worker(cycle)
        workers.append(worker)
        app.event_worker = worker
        await app._acquire("event worker", worker.start, worker.stop)

    monkeypatch.setattr(app, "initialize_auth", initialize_auth)
    monkeypatch.setattr(app, "initialize", initialize)
    monkeypatch.setattr(app, "start_services", start_services)
    monkeypatch.setattr("main.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("main.build_uvicorn_config", lambda config, api: object())
    monkeypatch.setattr("api.app.create_app", lambda config, auth_service: object())
    monkeypatch.setattr("uvicorn.Server", ReturningServer)
    return workers


@pytest.mark.asyncio
async def test_returning_server_cleans_owned_resources_and_database(monkeypatch):
    calls = []
    app = ParentalControlApp(AppConfig())
    _install_returning_server_runtime(app, monkeypatch, calls)

    await app.run()

    assert calls == [
        "database:1:open",
        "initialize:1",
        "worker:1:start",
        "server:return",
        "worker:1:stop",
        "database:1:close",
    ]
    assert app.event_worker is None
    assert not app._cleanup_stack
    assert not app._cleanup_tasks


@pytest.mark.asyncio
async def test_returning_server_allows_repeated_complete_lifecycle_cycles(monkeypatch):
    calls = []
    app = ParentalControlApp(AppConfig())
    workers = _install_returning_server_runtime(app, monkeypatch, calls)

    await app.run()
    await app.run()

    assert len(workers) == 2
    assert calls.count("server:return") == 2
    assert calls.count("worker:1:start") == calls.count("worker:1:stop") == 1
    assert calls.count("worker:2:start") == calls.count("worker:2:stop") == 1
    assert calls.count("database:1:open") == calls.count("database:1:close") == 1
    assert calls.count("database:2:open") == calls.count("database:2:close") == 1
    assert app.event_worker is None
    assert not app._cleanup_stack
    assert not app._cleanup_tasks
