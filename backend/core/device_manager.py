"""Device discovery and management using ARP scanning."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from scapy.all import ARP, Ether, srp, conf
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import async_session_factory, get_session
from db.models import Device
from utils.mac_utils import normalize_mac, lookup_vendor
from utils.network_utils import (
    get_default_gateway,
    get_network_subnet,
    get_hostname_from_ip,
    get_interface_mac,
)

logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


@dataclass
class DiscoveredDevice:
    """Represents a device discovered on the network."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None


class DeviceManager:
    """Manages network device discovery and tracking."""

    def __init__(self, interface: str):
        self.interface = interface
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.local_mac: Optional[str] = None
        self.subnet: Optional[str] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._running = False
        self._online_check_callbacks: List[callable] = []

    async def initialize(self):
        """Initialize device manager and detect network configuration."""
        logger.info(f"Initializing DeviceManager on interface {self.interface}")

        # Get local MAC
        self.local_mac = get_interface_mac(self.interface)
        logger.info(f"Local MAC: {self.local_mac}")

        # Get gateway
        gateway_info = get_default_gateway()
        if gateway_info:
            self.gateway_ip, gw_interface = gateway_info
            logger.info(f"Gateway IP: {self.gateway_ip} on {gw_interface}")

            # Get gateway MAC via ARP
            self.gateway_mac = await self._resolve_mac(self.gateway_ip)
            logger.info(f"Gateway MAC: {self.gateway_mac}")

        # Get subnet
        self.subnet = get_network_subnet(self.interface)
        logger.info(f"Network subnet: {self.subnet}")

        # Initialize database
        await self._init_db()

    async def _init_db(self):
        """Ensure database is initialized."""
        from db.database import init_db
        await init_db()

    async def _resolve_mac(self, ip: str) -> Optional[str]:
        """Resolve IP to MAC address using ARP."""
        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, iface=self.interface, timeout=3, retry=2, verbose=0)[0]

            if result:
                return normalize_mac(result[0][1].hwsrc)
        except Exception as e:
            logger.error(f"Failed to resolve MAC for {ip}: {e}")

        return None

    async def scan_network(self) -> List[DiscoveredDevice]:
        """
        Scan the network for devices using ARP.

        Returns:
            List of discovered devices
        """
        if not self.subnet:
            logger.error("No subnet configured for scanning")
            return []

        logger.info(f"Scanning network: {self.subnet}")
        discovered = []

        try:
            # Create ARP request packet
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send and receive
            result = srp(packet, iface=self.interface, timeout=5, retry=1, verbose=0)[0]

            for sent, received in result:
                mac = normalize_mac(received.hwsrc)
                ip = received.psrc

                # Skip our own MAC and gateway
                if mac == self.local_mac:
                    continue

                # Look up vendor and hostname
                vendor = lookup_vendor(mac)
                hostname = get_hostname_from_ip(ip)

                device = DiscoveredDevice(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    vendor=vendor
                )
                discovered.append(device)
                logger.debug(f"Discovered: {ip} ({mac}) - {vendor or 'Unknown vendor'}")

            logger.info(f"Scan complete: {len(discovered)} devices found")

        except Exception as e:
            logger.error(f"Network scan failed: {e}")

        return discovered

    async def update_devices_from_scan(self, discovered: List[DiscoveredDevice]) -> List[Device]:
        """
        Update database with discovered devices.

        Returns:
            List of updated Device models
        """
        updated_devices = []
        discovered_macs: Set[str] = set()

        async with get_session() as session:
            for disc in discovered:
                discovered_macs.add(disc.mac_address)

                # Check if device exists
                result = await session.execute(
                    select(Device).where(Device.mac_address == disc.mac_address)
                )
                device = result.scalar_one_or_none()

                if device:
                    # Update existing device
                    device.ip_address = disc.ip_address
                    device.is_online = True
                    device.last_seen = datetime.utcnow()

                    # Update hostname if we got one and didn't have one
                    if disc.hostname and not device.hostname:
                        device.hostname = disc.hostname

                    # Update vendor if we got one and didn't have one
                    if disc.vendor and not device.vendor:
                        device.vendor = disc.vendor
                else:
                    # Create new device
                    device = Device(
                        mac_address=disc.mac_address,
                        ip_address=disc.ip_address,
                        hostname=disc.hostname,
                        vendor=disc.vendor,
                        is_online=True,
                    )
                    session.add(device)

                updated_devices.append(device)

            # Mark devices not seen in scan as offline (if last seen > 5 minutes ago)
            offline_threshold = datetime.utcnow() - timedelta(minutes=5)
            await session.execute(
                update(Device)
                .where(Device.mac_address.notin_(discovered_macs))
                .where(Device.last_seen < offline_threshold)
                .values(is_online=False)
            )

            await session.commit()

            # Refresh to get IDs
            for device in updated_devices:
                await session.refresh(device)

        return updated_devices

    async def get_all_devices(self) -> List[Device]:
        """Get all devices from database."""
        async with get_session() as session:
            result = await session.execute(
                select(Device).order_by(Device.last_seen.desc())
            )
            return list(result.scalars().all())

    async def get_device_by_mac(self, mac: str) -> Optional[Device]:
        """Get device by MAC address."""
        normalized_mac = normalize_mac(mac)
        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address == normalized_mac)
            )
            return result.scalar_one_or_none()

    async def get_monitored_devices(self) -> List[Device]:
        """Get all devices marked for monitoring."""
        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.is_monitored == True)
            )
            return list(result.scalars().all())

    async def update_device(
        self,
        mac: str,
        friendly_name: Optional[str] = None,
        is_monitored: Optional[bool] = None,
        is_blocked: Optional[bool] = None,
    ) -> Optional[Device]:
        """Update device properties."""
        normalized_mac = normalize_mac(mac)

        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address == normalized_mac)
            )
            device = result.scalar_one_or_none()

            if not device:
                return None

            if friendly_name is not None:
                device.friendly_name = friendly_name
            if is_monitored is not None:
                device.is_monitored = is_monitored
            if is_blocked is not None:
                device.is_blocked = is_blocked

            await session.commit()
            await session.refresh(device)
            return device

    async def start_periodic_scan(self, interval_seconds: int = 30):
        """Start periodic network scanning in background."""
        self._running = True

        async def scan_loop():
            while self._running:
                try:
                    discovered = await self.scan_network()
                    devices = await self.update_devices_from_scan(discovered)

                    # Notify callbacks
                    for callback in self._online_check_callbacks:
                        await callback(devices)

                except Exception as e:
                    logger.error(f"Periodic scan error: {e}")

                await asyncio.sleep(interval_seconds)

        self._scan_task = asyncio.create_task(scan_loop())
        logger.info(f"Started periodic scanning every {interval_seconds}s")

    async def stop_periodic_scan(self):
        """Stop periodic network scanning."""
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
            self._scan_task = None
        logger.info("Stopped periodic scanning")

    def add_online_callback(self, callback: callable):
        """Add callback to be notified on device status changes."""
        self._online_check_callbacks.append(callback)

    def remove_online_callback(self, callback: callable):
        """Remove callback."""
        if callback in self._online_check_callbacks:
            self._online_check_callbacks.remove(callback)
