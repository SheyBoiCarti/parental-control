#!/usr/bin/env python3
"""Parental Control application entry point."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import sys
from typing import Any, Awaitable, Callable, Mapping

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import AppConfig, DEFAULT_ENV_FILE, load_config


@dataclass
class AppState:
    device_manager: Any
    arp_spoofer: Any
    packet_analyzer: Any
    traffic_controller: Any
    content_blocker: Any
    device_blocker: Any
    event_worker: Any = None
    reconciler: Any = None
    content_enforcer: Any = None
    bandwidth_monitor: Any = None
    reconciliation_worker: Any = None


def _component_types() -> dict[str, type[Any]]:
    """Import Linux/network modules only after CLI and config validation."""
    from core.arp_spoofer import ARPSpoofer
    from core.content_blocker import ContentBlocker
    from core.device_blocker import DeviceBlocker
    from core.device_manager import DeviceManager
    from core.packet_analyzer import PacketAnalyzer
    from core.traffic_controller import TrafficController

    return {
        "DeviceManager": DeviceManager,
        "ARPSpoofer": ARPSpoofer,
        "PacketAnalyzer": PacketAnalyzer,
        "TrafficController": TrafficController,
        "ContentBlocker": ContentBlocker,
        "DeviceBlocker": DeviceBlocker,
    }


def build_app_state(
    config: AppConfig,
    component_types: Mapping[str, type[Any]],
    *,
    gateway_mac: str | None,
    local_mac: str | None,
    local_ip: str | None = None,
) -> AppState:
    """Construct components from one config snapshot without starting them."""
    device_manager = component_types["DeviceManager"](
        interface=config.network_interface,
        gateway_ip=config.gateway_ip,
        network_subnet=config.network_subnet,
    )
    traffic_controller = component_types["TrafficController"](config.network_interface)
    if hasattr(traffic_controller, "set_ownership_file"):
        traffic_controller.set_ownership_file(config.data_dir / "traffic-controller-owner.json")
    return AppState(
        device_manager=device_manager,
        arp_spoofer=component_types["ARPSpoofer"](
            interface=config.network_interface,
            gateway_ip=config.gateway_ip,
            gateway_mac=gateway_mac,
            local_mac=local_mac,
            local_ip=local_ip,
            network_subnet=config.network_subnet,
        ),
        packet_analyzer=component_types["PacketAnalyzer"](config.network_interface),
        traffic_controller=traffic_controller,
        content_blocker=component_types["ContentBlocker"](),
        device_blocker=component_types["DeviceBlocker"](config.network_interface),
    )


def build_uvicorn_config(config: AppConfig, app: object):
    """Translate validated listener and proxy settings to the ASGI server."""
    import uvicorn

    trusted = ",".join(config.trusted_proxy_ips)
    return uvicorn.Config(
        app,
        host=config.api_host,
        port=config.api_port,
        log_level=config.log_level.lower(),
        ssl_certfile=str(config.https_cert_file) if config.https_cert_file else None,
        ssl_keyfile=str(config.https_key_file) if config.https_key_file else None,
        proxy_headers=bool(trusted),
        forwarded_allow_ips=trusted,
    )
class ParentalControlApp:
    def __init__(self, config: AppConfig):
        self.config = config
        self.state: AppState | None = None
        self.auth_service = None
        self.event_worker = None
        self.bandwidth_monitor = None
        self.reconciliation_worker = None
        self._cleanup_stack: list[tuple[str, Callable[[], Awaitable[Any]]]] = []
        self._cleanup_tasks: dict[
            tuple[str, Callable[[], Awaitable[Any]]], asyncio.Task[Any]
        ] = {}
        self._lifecycle_managed = False
        self._shutdown_deadline: float | None = None

    def _register_cleanup(
        self, name: str, cleanup: Callable[[], Awaitable[Any]]
    ) -> None:
        """Record an owned resource only after its acquisition succeeded."""
        self._lifecycle_managed = True
        self._cleanup_stack.append((name, cleanup))

    async def _acquire(
        self,
        name: str,
        start: Callable[[], Awaitable[Any]],
        cleanup: Callable[[], Awaitable[Any]],
    ) -> None:
        await start()
        self._register_cleanup(name, cleanup)

    async def _rollback_startup_failure(self) -> None:
        """Attempt every registered cleanup while preserving the startup error."""
        if not self._lifecycle_managed:
            return
        try:
            await self.stop_services()
        except BaseException:
            logging.getLogger(__name__).exception(
                "Cleanup after service startup failure was incomplete"
            )

    async def initialize_auth(self) -> None:
        from core.auth_service import AuthService
        from db.database import close_db, configure_database, init_db, get_session

        try:
            configure_database(self.config)
            self._register_cleanup("database", close_db)
            await init_db()
            self.auth_service = AuthService(get_session)
            await self.auth_service.ensure_configured()
        except BaseException:
            await self._rollback_startup_failure()
            raise

    async def initialize(self) -> None:
        from api.routes import devices, rules, settings, stats
        from core.reconciler import EnforcementReconciler
        from core.content_enforcer import ContentEnforcer
        from core.inline_inspector import InlineInspector
        from core.nfqueue_worker import NFQueueWorker
        from db.database import get_session
        try:
            if self.auth_service is None:
                await self.initialize_auth()
            types = _component_types()
            manager = types["DeviceManager"](
                interface=self.config.network_interface,
                gateway_ip=self.config.gateway_ip,
                network_subnet=self.config.network_subnet,
            )
            await manager.initialize()
            effective_config = self.config.model_copy(
                update={"gateway_ip": manager.gateway_ip, "network_subnet": manager.subnet}
            )
            self.state = build_app_state(
                effective_config,
                types,
                gateway_mac=manager.gateway_mac,
                local_mac=manager.local_mac,
                local_ip=manager.local_ip,
            )
            self.state.device_manager = manager
            await self.state.content_blocker.initialize()
            await self._acquire(
                "device blocker",
                self.state.device_blocker.initialize,
                self.state.device_blocker.shutdown,
            )
            inspector = InlineInspector(self.state.content_blocker)
            worker = NFQueueWorker(
                inspector,
                lambda event: self.event_worker.submit(event) if self.event_worker else False,
            )
            self.state.content_enforcer = ContentEnforcer(
                effective_config.network_interface,
                inspector,
                worker=worker,
            )
            self.state.reconciler = EnforcementReconciler(
                get_session,
                self.state.arp_spoofer,
                self.state.device_blocker,
                self.state.traffic_controller,
                self.state.content_enforcer,
            )
            devices.set_app_state(self.state)
            rules.set_app_state(self.state)
            stats.set_app_state(self.state)
            settings.set_app_state(self.state)
            self._setup_packet_callbacks()
        except BaseException:
            await self._rollback_startup_failure()
            raise

    def _setup_packet_callbacks(self) -> None:
        from core.packet_events import AccessEvent
        assert self.state is not None

        def observed(mac, domain):
            if self.event_worker is not None:
                # Passive capture observes traffic; only an inline verdict can
                # truthfully produce a blocked event.
                self.event_worker.submit(AccessEvent(mac, domain, "allowed"))

        self.state.packet_analyzer.add_dns_callback(
            lambda query: observed(query.src_mac, query.domain)
        )
        self.state.packet_analyzer.add_tls_callback(
            lambda connection: observed(connection.src_mac, connection.sni)
        )

    async def start_services(self) -> None:
        from api.websocket import ws_manager
        from core.bandwidth_monitor import BandwidthMonitor
        from core.packet_events import EventWorker, persist_events
        from core.reconciliation_worker import ReconciliationWorker
        from db.database import get_session
        assert self.state is not None
        try:
            self.event_worker = EventWorker(
                persist_events, capacity=self.config.event_queue_capacity,
                batch_size=self.config.event_batch_size,
                flush_seconds=self.config.event_flush_seconds,
            )
            await self._acquire("event worker", self.event_worker.start, self.event_worker.stop)
            self.state.event_worker = self.event_worker

            async def on_device_scan(devices) -> None:
                from api.websocket import ws_manager

                assert self.state is not None
                for device in devices:
                    await self.state.reconciler.reconcile(device.mac_address)
                mapping = {device.ip_address: device.mac_address for device in devices if device.ip_address}
                self.state.packet_analyzer.set_ip_mac_mapping(mapping)
                await ws_manager.broadcast_devices_list([device.to_dict() for device in devices])

            self.state.device_manager.add_online_callback(on_device_scan)
            await self._start_network_enforcement()
            self.reconciliation_worker = ReconciliationWorker(
                self.state.reconciler,
                interval_seconds=self.config.reconciliation_interval_seconds,
            )
            await self._acquire(
                "reconciliation worker",
                self.reconciliation_worker.start,
                self.reconciliation_worker.stop,
            )
            self.state.reconciliation_worker = self.reconciliation_worker
            self.bandwidth_monitor = BandwidthMonitor(
                self.state.traffic_controller,
                get_session,
                ws_manager.broadcast_bandwidth_stats,
                interval_seconds=self.config.accounting_interval_seconds,
                retention_days=self.config.telemetry_retention_days,
                prune_interval_seconds=self.config.retention_prune_interval_seconds,
            )
            await self._acquire(
                "bandwidth monitor",
                self.bandwidth_monitor.start,
                self.bandwidth_monitor.stop,
            )
            self.state.bandwidth_monitor = self.bandwidth_monitor
            await self._acquire(
                "periodic device scan",
                lambda: self.state.device_manager.start_periodic_scan(self.config.device_scan_interval),
                self.state.device_manager.stop_periodic_scan,
            )
        except BaseException:
            await self._rollback_startup_failure()
            raise

    async def _start_network_enforcement(self) -> None:
        """Prepare owned rules and persisted intent before traffic interception."""
        assert self.state is not None
        await self._acquire(
            "traffic controller",
            self.state.traffic_controller.initialize,
            self.state.traffic_controller.shutdown,
        )
        await self._acquire(
            "content enforcer",
            self.state.content_enforcer.initialize,
            self.state.content_enforcer.shutdown,
        )
        await self.state.reconciler.reset_runtime_state()
        await self.state.reconciler.reconcile_all()
        await self._acquire("ARP spoofer", self.state.arp_spoofer.start, self.state.arp_spoofer.stop)
        await self._acquire(
            "packet analyzer", self.state.packet_analyzer.start, self.state.packet_analyzer.stop
        )

    def _shutdown_deadline_for(self, timeout: float) -> float:
        loop = asyncio.get_running_loop()
        if self._shutdown_deadline is None:
            self._shutdown_deadline = loop.time() + timeout
        return self._shutdown_deadline

    def _observe_cleanup_task(
        self,
        action: tuple[str, Callable[[], Awaitable[Any]]],
        task: asyncio.Task[Any],
    ) -> None:
        try:
            error = task.exception()
        except asyncio.CancelledError:
            logging.getLogger(__name__).error("%s cleanup task was cancelled", action[0])
            return
        if error is not None:
            logging.getLogger(__name__).error(
                "%s cleanup task failed after shutdown advanced",
                action[0],
                exc_info=(type(error), error, error.__traceback__),
            )

    async def stop_services(self, timeout: float = 10.0) -> None:
        from db.database import close_db

        if self._lifecycle_managed:
            cleanup = list(reversed(self._cleanup_stack))
        else:
            cleanup = self._legacy_cleanup_actions(close_db)
        failures = []
        completed = []
        loop = asyncio.get_running_loop()
        deadline = self._shutdown_deadline_for(timeout)
        for index, action in enumerate(cleanup):
            name, stop = action
            remaining = max(0.0, deadline - loop.time())
            operations_left = len(cleanup) - index
            operation_timeout = max(0.001, remaining / operations_left)
            task = self._cleanup_tasks.get(action)
            if task is None:
                try:
                    task = asyncio.create_task(stop(), name=f"cleanup-{name}")
                except Exception as error:
                    logging.getLogger(__name__).exception("%s cleanup could not start", name)
                    failures.append(error)
                    continue
                self._cleanup_tasks[action] = task
                task.add_done_callback(
                    lambda done, current=action: self._observe_cleanup_task(current, done)
                )
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=operation_timeout)
            except TimeoutError:
                logging.getLogger(__name__).error("%s cleanup exceeded its shutdown budget", name)
                task.cancel()
                failures.append(RuntimeError(f"{name} cleanup timed out"))
            except asyncio.CancelledError:
                logging.getLogger(__name__).error("%s cleanup was cancelled", name)
                failures.append(RuntimeError(f"{name} cleanup was cancelled"))
                if task.done():
                    self._cleanup_tasks.pop(action, None)
            except Exception as error:
                logging.getLogger(__name__).exception("%s cleanup failed", name)
                failures.append(error)
                self._cleanup_tasks.pop(action, None)
            else:
                completed.append(action)
                self._cleanup_tasks.pop(action, None)
                self._mark_cleaned(name)
        if self._lifecycle_managed and completed:
            self._cleanup_stack = [action for action in self._cleanup_stack if action not in completed]
        if not self._cleanup_stack and not self._cleanup_tasks:
            self._shutdown_deadline = None
        if failures:
            raise ExceptionGroup("Service shutdown failed", failures)

    def _legacy_cleanup_actions(
        self, close_db: Callable[[], Awaitable[Any]]
    ) -> list[tuple[str, Callable[[], Awaitable[Any]]]]:
        acquired: list[tuple[str, Callable[[], Awaitable[Any]]]] = []
        if self.state is not None:
            acquired.append(("device blocker", self.state.device_blocker.shutdown))
        if self.event_worker is not None:
            acquired.append(("event worker", self.event_worker.stop))
        if self.state is not None:
            acquired.append(("traffic controller", self.state.traffic_controller.shutdown))
            if getattr(self.state, "content_enforcer", None) is not None:
                acquired.append(("content enforcer", self.state.content_enforcer.shutdown))
            acquired.extend([
                ("ARP spoofer", self.state.arp_spoofer.stop),
                ("packet analyzer", self.state.packet_analyzer.stop),
            ])
            if getattr(self.state, "reconciliation_worker", None) is not None:
                acquired.append(("reconciliation worker", self.state.reconciliation_worker.stop))
            if getattr(self.state, "bandwidth_monitor", None) is not None:
                acquired.append(("bandwidth monitor", self.state.bandwidth_monitor.stop))
            acquired.append(("periodic device scan", self.state.device_manager.stop_periodic_scan))
        return list(reversed(acquired)) + [("database", close_db)]

    def _mark_cleaned(self, name: str) -> None:
        if name == "event worker":
            self.event_worker = None
            if self.state is not None:
                self.state.event_worker = None
        elif name == "reconciliation worker":
            self.reconciliation_worker = None
            if self.state is not None:
                self.state.reconciliation_worker = None
        elif name == "bandwidth monitor":
            self.bandwidth_monitor = None
            if self.state is not None:
                self.state.bandwidth_monitor = None

    async def run(self) -> None:
        import uvicorn
        from api.app import create_app

        primary_error: BaseException | None = None
        try:
            await self.initialize_auth()
            if not hasattr(os, "geteuid") or os.geteuid() != 0:
                raise RuntimeError("Network enforcement requires root privileges on Linux")
            await self.initialize()
            await self.start_services()
            uvicorn_config = build_uvicorn_config(self.config, create_app(self.config, auth_service=self.auth_service))
            await uvicorn.Server(uvicorn_config).serve()
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if self._lifecycle_managed:
                try:
                    await self.stop_services()
                except BaseException:
                    if primary_error is None:
                        raise
                    logging.getLogger(__name__).exception(
                        "Service shutdown failed after application failure"
                    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parental Control Network Management System")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("-i", "--interface", dest="network_interface")
    parser.add_argument("-p", "--port", dest="api_port", type=int)
    parser.add_argument("--host", dest="api_host")
    parser.add_argument("--gateway", dest="gateway_ip")
    parser.add_argument("--subnet", dest="network_subnet")
    parser.add_argument("--reset-password", action="store_true", help="Set the local administrator password without starting network services")
    parser.add_argument("--username", dest="auth_username")
    return parser


def _require_startup_credentials(config: AppConfig) -> None:
    if not config.auth_password_hash and not config.db_path.is_file():
        raise ValueError(
            "No administrator credential: set AUTH_PASSWORD_HASH or run --reset-password locally"
        )


async def reset_admin_password(config: AppConfig, password: str) -> None:
    from core.auth_service import AuthService
    from db.database import configure_database, init_db, get_session, close_db
    try:
        configure_database(config)
        await init_db()
        await AuthService(get_session).reset_password(config.auth_username, password)
    finally:
        await close_db()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from core.auth_service import AuthUnavailable
    from sqlalchemy.exc import SQLAlchemyError
    cli = vars(args).copy()
    env_file = cli.pop("env_file")
    reset = cli.pop("reset_password")
    try:
        config = load_config(env_file, cli)
        if reset:
            import getpass
            password = getpass.getpass("New administrator password: ")
            if password != getpass.getpass("Confirm password: "):
                parser.error("Passwords do not match")
            asyncio.run(reset_admin_password(config, password))
            return 0
        _require_startup_credentials(config)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    except SQLAlchemyError:
        parser.error("Database unavailable; check its path and permissions")
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    try:
        asyncio.run(ParentalControlApp(config).run())
    except (RuntimeError, AuthUnavailable) as error:
        parser.error(str(error))
    except SQLAlchemyError:
        parser.error("Database unavailable; check its path and permissions")
    return 0


if __name__ == "__main__":
    main()
