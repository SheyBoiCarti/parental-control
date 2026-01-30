#!/usr/bin/env python3
"""
Parental Control Network Management System

Main entry point for the application.
Requires root/sudo for network operations (ARP, iptables, tc).
"""

import asyncio
import logging
import signal
import sys
import os
from dataclasses import dataclass
from typing import Optional

import uvicorn

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    NETWORK_INTERFACE, GATEWAY_IP, API_HOST, API_PORT,
    LOG_LEVEL, LOG_FILE, DATA_DIR, DEVICE_SCAN_INTERVAL
)
from db.database import init_db, close_db
from core import (
    DeviceManager, ARPSpoofer, PacketAnalyzer,
    TrafficController, ContentBlocker, DeviceBlocker
)
from api.app import create_app
from api.websocket import ws_manager
from api.routes import devices, rules, stats, settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE) if LOG_FILE.parent.exists() else logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class AppState:
    """Application state container."""
    device_manager: DeviceManager
    arp_spoofer: ARPSpoofer
    packet_analyzer: PacketAnalyzer
    traffic_controller: TrafficController
    content_blocker: ContentBlocker
    device_blocker: DeviceBlocker


class ParentalControlApp:
    """Main application class."""

    def __init__(self, interface: str):
        self.interface = interface
        self.state: Optional[AppState] = None
        self._shutdown_event = asyncio.Event()

    async def initialize(self):
        """Initialize all components."""
        logger.info(f"Initializing Parental Control System on {self.interface}")

        # Ensure data directory exists
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize database
        await init_db()
        logger.info("Database initialized")

        # Initialize device manager
        device_manager = DeviceManager(self.interface)
        await device_manager.initialize()

        # Initialize ARP spoofer
        arp_spoofer = ARPSpoofer(
            interface=self.interface,
            gateway_ip=device_manager.gateway_ip,
            gateway_mac=device_manager.gateway_mac,
            local_mac=device_manager.local_mac
        )

        # Initialize packet analyzer
        packet_analyzer = PacketAnalyzer(self.interface)

        # Initialize traffic controller
        traffic_controller = TrafficController(self.interface)

        # Initialize content blocker
        content_blocker = ContentBlocker()
        await content_blocker.initialize()

        # Initialize device blocker
        device_blocker = DeviceBlocker(self.interface)
        await device_blocker.initialize()

        # Create app state
        self.state = AppState(
            device_manager=device_manager,
            arp_spoofer=arp_spoofer,
            packet_analyzer=packet_analyzer,
            traffic_controller=traffic_controller,
            content_blocker=content_blocker,
            device_blocker=device_blocker
        )

        # Set state in API routes
        devices.set_app_state(self.state)
        rules.set_app_state(self.state)
        stats.set_app_state(self.state)
        settings.set_app_state(self.state)

        # Setup packet analyzer callbacks
        self._setup_packet_callbacks()

        # Sync blocked devices from database
        await device_blocker.sync_from_database()

        logger.info("All components initialized")

    def _setup_packet_callbacks(self):
        """Setup callbacks for packet analyzer."""

        def on_dns_query(query):
            """Handle DNS query detection."""
            # Check if domain should be blocked
            block_reason = self.state.content_blocker.should_block(
                query.src_mac, query.domain
            )

            if block_reason:
                logger.info(f"Blocked DNS: {query.domain} for {query.src_mac} ({block_reason})")
                # Log blocked access
                asyncio.create_task(self._log_access(
                    query.src_mac, query.domain, "blocked", block_reason
                ))
            else:
                # Log allowed access (optional, can be disabled for performance)
                asyncio.create_task(self._log_access(
                    query.src_mac, query.domain, "allowed", None
                ))

        def on_tls_connection(conn):
            """Handle TLS connection detection."""
            block_reason = self.state.content_blocker.should_block(
                conn.src_mac, conn.sni
            )

            if block_reason:
                logger.info(f"Detected TLS to blocked domain: {conn.sni} ({block_reason})")
                asyncio.create_task(self._log_access(
                    conn.src_mac, conn.sni, "blocked", block_reason
                ))

        self.state.packet_analyzer.add_dns_callback(on_dns_query)
        self.state.packet_analyzer.add_tls_callback(on_tls_connection)

    async def _log_access(self, mac: str, domain: str, action: str, app_name: Optional[str]):
        """Log domain access to database."""
        from db.database import get_session
        from db.models import Device, AccessLog
        from sqlalchemy import select

        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Device).where(Device.mac_address == mac)
                )
                device = result.scalar_one_or_none()

                if device:
                    log = AccessLog(
                        device_id=device.id,
                        domain=domain,
                        action=action,
                        app_name=app_name
                    )
                    session.add(log)
                    await session.commit()

                    # Broadcast to websocket clients
                    await ws_manager.broadcast_access_log({
                        "mac": mac,
                        "domain": domain,
                        "action": action,
                        "app": app_name
                    })
        except Exception as e:
            logger.error(f"Failed to log access: {e}")

    async def start_services(self):
        """Start background services."""
        logger.info("Starting background services")

        # Start device scanning
        await self.state.device_manager.start_periodic_scan(DEVICE_SCAN_INTERVAL)

        # Setup callback for device updates
        async def on_device_scan(devices):
            # Update IP-MAC mapping for packet analyzer
            mapping = {d.ip_address: d.mac_address for d in devices if d.ip_address}
            self.state.packet_analyzer.set_ip_mac_mapping(mapping)

            # Broadcast device updates
            await ws_manager.broadcast_devices_list([d.to_dict() for d in devices])

            # Re-add monitored devices to ARP spoofer if their IP changed
            for device in devices:
                if device.is_monitored and device.ip_address:
                    if device.mac_address in self.state.arp_spoofer.active_targets:
                        await self.state.arp_spoofer.update_target_ip(
                            device.mac_address, device.ip_address
                        )

        self.state.device_manager.add_online_callback(on_device_scan)

        # Start ARP spoofer
        await self.state.arp_spoofer.start()

        # Start packet analyzer
        await self.state.packet_analyzer.start()

        # Initialize traffic controller
        await self.state.traffic_controller.initialize()

        logger.info("All services started")

    async def stop_services(self):
        """Stop all background services gracefully."""
        logger.info("Stopping services...")

        if self.state:
            # Stop periodic scanning
            await self.state.device_manager.stop_periodic_scan()

            # Stop ARP spoofer (restores ARP tables)
            await self.state.arp_spoofer.stop()

            # Stop packet analyzer
            await self.state.packet_analyzer.stop()

            # Shutdown traffic controller
            await self.state.traffic_controller.shutdown()

            # Shutdown device blocker
            await self.state.device_blocker.shutdown()

        # Close database
        await close_db()

        logger.info("All services stopped")

    async def run(self):
        """Run the application."""
        # Check root privileges
        if os.geteuid() != 0:
            logger.error("This application requires root privileges")
            logger.error("Please run with sudo")
            sys.exit(1)

        await self.initialize()
        await self.start_services()

        # Create FastAPI app
        app = create_app()

        # Setup signal handlers
        loop = asyncio.get_event_loop()

        def signal_handler():
            logger.info("Shutdown signal received")
            self._shutdown_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)

        # Run uvicorn server
        config = uvicorn.Config(
            app,
            host=API_HOST,
            port=API_PORT,
            log_level=LOG_LEVEL.lower(),
            access_log=True
        )
        server = uvicorn.Server(config)

        # Run server until shutdown
        try:
            await server.serve()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop_services()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Parental Control Network Management System"
    )
    parser.add_argument(
        "-i", "--interface",
        default=NETWORK_INTERFACE,
        help=f"Network interface (default: {NETWORK_INTERFACE})"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=API_PORT,
        help=f"API port (default: {API_PORT})"
    )
    parser.add_argument(
        "--host",
        default=API_HOST,
        help=f"API host (default: {API_HOST})"
    )

    args = parser.parse_args()

    # Override config with command line args
    global API_PORT, API_HOST
    API_PORT = args.port
    API_HOST = args.host

    # Run application
    app = ParentalControlApp(args.interface)
    asyncio.run(app.run())


if __name__ == "__main__":
    main()
