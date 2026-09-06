"""Device blocker using iptables for complete network blocking."""

import logging
from typing import Set

from utils.commands import CommandRunner, CommandError
from utils.mac_utils import normalize_mac

logger = logging.getLogger(__name__)


class DeviceBlocker:
    """
    Blocks devices from network access using iptables.

    Uses MAC-based filtering to completely block a device's
    network access at the firewall level.
    """

    def __init__(self, interface: str, *, runner=None):
        self._runner = runner if runner is not None else CommandRunner()
        self.interface = interface
        self._blocked_macs: Set[str] = set()
        self._chain_name = "PARENTAL_BLOCK"
        self._initialized = False

    async def initialize(self):
        """Initialize iptables chain for blocking."""
        if self._initialized:
            return

        # Probe before creating; an existing chain must never be flushed here.
        result = await self._runner.run(
            ["iptables", "-S", self._chain_name], check=False
        )
        if result.returncode == 1:
            await self._runner.run(["iptables", "-N", self._chain_name])
        elif result.returncode:
            raise CommandError("iptables", result)

        for parent in ("FORWARD", "INPUT"):
            result = await self._runner.run(
                ["iptables", "-C", parent, "-j", self._chain_name], check=False
            )
            if result.returncode == 1:
                await self._runner.run(["iptables", "-I", parent, "-j", self._chain_name])
            elif result.returncode:
                raise CommandError("iptables", result)

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
            ret, _, err = await self._runner.run([
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
            ret, _, err = await self._runner.run([
                "iptables", "-D", self._chain_name,
                "-m", "mac", "--mac-source", normalized_mac,
                "-j", "DROP"
            ])

            self._blocked_macs.discard(normalized_mac)

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

        failures = []
        for mac in list(self._blocked_macs):
            if not await self.unblock_device(mac):
                failures.append(mac)
        if failures:
            raise RuntimeError("Failed to remove device blocks during shutdown")

        for parent in ("FORWARD", "INPUT"):
            result = await self._runner.run(
                ["iptables", "-C", parent, "-j", self._chain_name], check=False
            )
            if result.returncode == 0:
                await self._runner.run(["iptables", "-D", parent, "-j", self._chain_name])
            elif result.returncode != 1:
                raise CommandError("iptables", result)

        # Deletion fails if untracked rules remain; never flush them away.
        await self._runner.run(["iptables", "-X", self._chain_name])
        self._initialized = False
        logger.info("Device blocker shutdown complete")
