"""Device blocker using iptables for complete network blocking."""

import logging
from typing import Set

from utils.network_utils import run_command
from utils.mac_utils import normalize_mac

logger = logging.getLogger(__name__)


class DeviceBlocker:
    """
    Blocks devices from network access using iptables.

    Uses MAC-based filtering to completely block a device's
    network access at the firewall level.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._blocked_macs: Set[str] = set()
        self._chain_name = "PARENTAL_BLOCK"
        self._initialized = False

    async def initialize(self):
        """Initialize iptables chain for blocking."""
        if self._initialized:
            return

        # Create custom chain
        ret, _, _ = run_command(
            ["iptables", "-N", self._chain_name],
            check=False
        )

        # Flush chain if it already existed
        run_command(
            ["iptables", "-F", self._chain_name],
            check=False
        )

        # Add jump to our chain from FORWARD (for traffic passing through)
        ret, stdout, _ = run_command(
            ["iptables", "-C", "FORWARD", "-j", self._chain_name],
            check=False
        )
        if ret != 0:
            run_command(
                ["iptables", "-I", "FORWARD", "-j", self._chain_name],
                check=False
            )

        # Also add to INPUT for traffic to this host
        ret, _, _ = run_command(
            ["iptables", "-C", "INPUT", "-j", self._chain_name],
            check=False
        )
        if ret != 0:
            run_command(
                ["iptables", "-I", "INPUT", "-j", self._chain_name],
                check=False
            )

        self._initialized = True
        logger.info("Device blocker initialized")

    async def block_device(self, mac: str) -> bool:
        """
        Block a device's network access.

        Args:
            mac: Device MAC address

        Returns:
            True if blocked successfully
        """
        if not self._initialized:
            await self.initialize()

        normalized_mac = normalize_mac(mac)

        if normalized_mac in self._blocked_macs:
            logger.info(f"Device {normalized_mac} already blocked")
            return True

        try:
            # Block incoming traffic from this MAC
            ret, _, err = run_command([
                "iptables", "-A", self._chain_name,
                "-m", "mac", "--mac-source", normalized_mac,
                "-j", "DROP"
            ])

            if ret != 0:
                logger.error(f"Failed to block {normalized_mac}: {err}")
                return False

            self._blocked_macs.add(normalized_mac)
            logger.info(f"Blocked device: {normalized_mac}")
            return True

        except Exception as e:
            logger.error(f"Error blocking device {normalized_mac}: {e}")
            return False

    async def unblock_device(self, mac: str) -> bool:
        """
        Unblock a device's network access.

        Args:
            mac: Device MAC address

        Returns:
            True if unblocked successfully
        """
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._blocked_macs:
            logger.info(f"Device {normalized_mac} not blocked")
            return True

        try:
            # Remove the DROP rule
            ret, _, err = run_command([
                "iptables", "-D", self._chain_name,
                "-m", "mac", "--mac-source", normalized_mac,
                "-j", "DROP"
            ], check=False)

            # Even if command fails, remove from our tracking
            self._blocked_macs.discard(normalized_mac)

            if ret != 0:
                logger.warning(f"iptables rule removal may have failed: {err}")

            logger.info(f"Unblocked device: {normalized_mac}")
            return True

        except Exception as e:
            logger.error(f"Error unblocking device {normalized_mac}: {e}")
            return False

    def is_blocked(self, mac: str) -> bool:
        """Check if a device is blocked."""
        return normalize_mac(mac) in self._blocked_macs

    def get_blocked_devices(self) -> Set[str]:
        """Get set of blocked MAC addresses."""
        return self._blocked_macs.copy()

    async def sync_from_database(self):
        """Sync blocked devices from database."""
        from db.database import get_session
        from db.models import Device
        from sqlalchemy import select

        async with get_session() as session:
            result = await session.execute(
                select(Device).where(Device.is_blocked == True)
            )
            blocked_devices = result.scalars().all()

            for device in blocked_devices:
                if device.mac_address not in self._blocked_macs:
                    await self.block_device(device.mac_address)

        logger.info(f"Synced {len(self._blocked_macs)} blocked devices from database")

    async def shutdown(self):
        """Clean up iptables rules."""
        logger.info("Shutting down device blocker")

        # Unblock all devices
        for mac in list(self._blocked_macs):
            await self.unblock_device(mac)

        # Remove chain references
        run_command(
            ["iptables", "-D", "FORWARD", "-j", self._chain_name],
            check=False
        )
        run_command(
            ["iptables", "-D", "INPUT", "-j", self._chain_name],
            check=False
        )

        # Flush and delete chain
        run_command(
            ["iptables", "-F", self._chain_name],
            check=False
        )
        run_command(
            ["iptables", "-X", self._chain_name],
            check=False
        )

        self._initialized = False
        logger.info("Device blocker shutdown complete")
