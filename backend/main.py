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
from typing import Any, Mapping

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
) -> AppState:
    """Construct components from one config snapshot without starting them."""
    device_manager = component_types["DeviceManager"](
        interface=config.network_interface,
        gateway_ip=config.gateway_ip,
        network_subnet=config.network_subnet,
    )
    return AppState(
        device_manager=device_manager,
        arp_spoofer=component_types["ARPSpoofer"](
            interface=config.network_interface,
            gateway_ip=config.gateway_ip,
            gateway_mac=gateway_mac,
            local_mac=local_mac,
        ),
        packet_analyzer=component_types["PacketAnalyzer"](config.network_interface),
        traffic_controller=component_types["TrafficController"](config.network_interface),
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

    async def initialize_auth(self) -> None:
        from core.auth_service import AuthService
        from db.database import configure_database, init_db, get_session
        configure_database(self.config)
        await init_db()
        self.auth_service = AuthService(get_session)
        await self.auth_service.ensure_configured()

    async def initialize(self) -> None:
        from api.routes import devices, rules, settings, stats
        from core.reconciler import EnforcementReconciler
        from db.database import get_session
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
        )
        self.state.device_manager = manager
        await self.state.content_blocker.initialize()
        await self.state.device_blocker.initialize()
        self.state.reconciler = EnforcementReconciler(
            get_session,
            self.state.arp_spoofer,
            self.state.device_blocker,
            self.state.traffic_controller,
        )
        devices.set_app_state(self.state)
        rules.set_app_state(self.state)
        stats.set_app_state(self.state)
        settings.set_app_state(self.state)
        self._setup_packet_callbacks()

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
        from core.packet_events import EventWorker, persist_events
        assert self.state is not None
        self.event_worker = EventWorker(
            persist_events, capacity=self.config.event_queue_capacity,
            batch_size=self.config.event_batch_size,
            flush_seconds=self.config.event_flush_seconds,
        )
        await self.event_worker.start()
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
        await self.state.device_manager.start_periodic_scan(self.config.device_scan_interval)

    async def _start_network_enforcement(self) -> None:
        """Prepare owned rules and persisted intent before traffic interception."""
        assert self.state is not None
        await self.state.traffic_controller.initialize()
        await self.state.reconciler.reset_runtime_state()
        await self.state.reconciler.reconcile_all()
        await self.state.arp_spoofer.start()
        await self.state.packet_analyzer.start()

    async def stop_services(self) -> None:
        from db.database import close_db

        cleanup = []
        if self.state is not None:
            cleanup.extend([
                self.state.device_manager.stop_periodic_scan,
                self.state.arp_spoofer.stop,
                self.state.packet_analyzer.stop,
                self.state.traffic_controller.shutdown,
                self.state.device_blocker.shutdown,
            ])
        if self.event_worker is not None:
            cleanup.append(self.event_worker.stop)
        cleanup.append(close_db)
        failures = []
        for stop in cleanup:
            try:
                await stop()
            except Exception as error:
                logging.getLogger(__name__).exception("Service cleanup failed")
                failures.append(error)
        if failures:
            raise ExceptionGroup("Service shutdown failed", failures)

    async def run(self) -> None:
        import uvicorn
        from api.app import create_app

        try:
            await self.initialize_auth()
            if not hasattr(os, "geteuid") or os.geteuid() != 0:
                raise RuntimeError("Network enforcement requires root privileges on Linux")
            await self.initialize()
            await self.start_services()
            uvicorn_config = build_uvicorn_config(self.config, create_app(self.config, auth_service=self.auth_service))
            await uvicorn.Server(uvicorn_config).serve()
        finally:
            await self.stop_services()


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
