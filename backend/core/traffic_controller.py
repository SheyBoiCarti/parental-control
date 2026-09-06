"""Traffic controller using Linux tc for bandwidth limiting."""

import asyncio
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from utils.commands import CommandRunner
from utils.mac_utils import normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class BandwidthLimit:
    """Bandwidth limit configuration."""
    mac_address: str
    download_kbps: int  # Download limit in Kbps
    upload_kbps: int    # Upload limit in Kbps
    class_id: int       # tc class ID


class TrafficController:
    """
    Controls bandwidth using Linux Traffic Control (tc).

    Uses HTB (Hierarchical Token Bucket) for rate limiting
    with iptables MARK to classify packets by MAC address.
    """

    def __init__(self, interface: str, *, runner=None):
        self._runner = runner if runner is not None else CommandRunner()
        self.interface = interface
        self._limits: Dict[str, BandwidthLimit] = {}  # MAC -> BandwidthLimit
        self._next_class_id = 10
        self._initialized = False

        # IFB (Intermediate Functional Block) for ingress shaping
        self.ifb_interface = "ifb0"

    async def initialize(self):
        """Initialize tc qdisc and classes."""
        if self._initialized:
            return

        logger.info("Initializing traffic controller")

        # Clean up any existing configuration
        await self._cleanup()

        # Load IFB module for ingress shaping
        await self._setup_ifb()

        # Setup HTB qdisc on main interface (egress/upload)
        await self._run_tc([
            "qdisc", "add", "dev", self.interface,
            "root", "handle", "1:", "htb", "default", "9999"
        ])

        # Root class with maximum bandwidth (1Gbps)
        await self._run_tc([
            "class", "add", "dev", self.interface,
            "parent", "1:", "classid", "1:1",
            "htb", "rate", "1000mbit", "ceil", "1000mbit"
        ])

        # Default class for unlimited traffic
        await self._run_tc([
            "class", "add", "dev", self.interface,
            "parent", "1:1", "classid", "1:9999",
            "htb", "rate", "1000mbit", "ceil", "1000mbit"
        ])

        # Setup HTB on IFB interface (ingress/download)
        await self._run_tc([
            "qdisc", "add", "dev", self.ifb_interface,
            "root", "handle", "1:", "htb", "default", "9999"
        ])

        await self._run_tc([
            "class", "add", "dev", self.ifb_interface,
            "parent", "1:", "classid", "1:1",
            "htb", "rate", "1000mbit", "ceil", "1000mbit"
        ])

        await self._run_tc([
            "class", "add", "dev", self.ifb_interface,
            "parent", "1:1", "classid", "1:9999",
            "htb", "rate", "1000mbit", "ceil", "1000mbit"
        ])

        self._initialized = True
        logger.info("Traffic controller initialized")

    async def _setup_ifb(self):
        """Setup IFB interface for ingress traffic shaping."""
        # Load IFB kernel module
        await self._runner.run(["modprobe", "ifb", "numifbs=1"])

        # Bring up IFB interface
        await self._runner.run(["ip", "link", "set", "dev", self.ifb_interface, "up"])

        # Redirect ingress traffic to IFB
        await self._run_tc([
            "qdisc", "add", "dev", self.interface,
            "ingress", "handle", "ffff:"
        ])

        await self._run_tc([
            "filter", "add", "dev", self.interface,
            "parent", "ffff:", "protocol", "ip", "u32",
            "match", "u32", "0", "0",
            "action", "mirred", "egress", "redirect", "dev", self.ifb_interface
        ])

    async def _cleanup(self):
        """Clean up tc configuration."""
        # Remove qdisc from main interface
        await self._run_tc(["qdisc", "del", "dev", self.interface, "root"], check=False)
        await self._run_tc(["qdisc", "del", "dev", self.interface, "ingress"], check=False)

        # Remove qdisc from IFB
        await self._run_tc(["qdisc", "del", "dev", self.ifb_interface, "root"], check=False)

        # Clean up iptables marks
        await self._cleanup_iptables_marks()

    async def _cleanup_iptables_marks(self):
        """Remove only exact mark rules tracked by this controller."""
        for mac, limit in self._limits.items():
            await self._runner.run([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-m", "mac", "--mac-source", mac,
                "-j", "MARK", "--set-mark", str(limit.class_id),
            ])

    async def _run_tc(self, args: list, check: bool = True) -> Tuple[int, str, str]:
        """Run tc command."""
        cmd = ["tc"] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        return await self._runner.run(cmd, check=check)

    def _get_next_class_id(self) -> int:
        """Get next available class ID."""
        class_id = self._next_class_id
        self._next_class_id += 1
        return class_id

    async def set_bandwidth_limit(
        self,
        mac: str,
        download_kbps: int,
        upload_kbps: int
    ) -> bool:
        """
        Set bandwidth limit for a device.

        Args:
            mac: Device MAC address
            download_kbps: Download limit in Kbps
            upload_kbps: Upload limit in Kbps

        Returns:
            True if successful
        """
        if not self._initialized:
            await self.initialize()

        normalized_mac = normalize_mac(mac)

        # Remove existing limit if present
        if normalized_mac in self._limits:
            if not await self.remove_bandwidth_limit(normalized_mac):
                return False

        class_id = self._get_next_class_id()

        try:
            # Create tc class for upload (egress on main interface)
            await self._run_tc([
                "class", "add", "dev", self.interface,
                "parent", "1:1", "classid", f"1:{class_id}",
                "htb", "rate", f"{upload_kbps}kbit", "ceil", f"{upload_kbps}kbit"
            ])

            # Create tc class for download (egress on IFB)
            await self._run_tc([
                "class", "add", "dev", self.ifb_interface,
                "parent", "1:1", "classid", f"1:{class_id}",
                "htb", "rate", f"{download_kbps}kbit", "ceil", f"{download_kbps}kbit"
            ])

            # Use iptables to mark packets by MAC for upload
            await self._runner.run([
                "iptables", "-t", "mangle", "-A", "PREROUTING",
                "-m", "mac", "--mac-source", normalized_mac,
                "-j", "MARK", "--set-mark", str(class_id)
            ])

            # Add tc filter to match marked packets (upload)
            await self._run_tc([
                "filter", "add", "dev", self.interface,
                "parent", "1:", "protocol", "ip",
                "handle", str(class_id), "fw",
                "flowid", f"1:{class_id}"
            ])

            # For download, we need to mark packets going TO the device
            # This is trickier - we need the device's IP
            # For now, mark by destination MAC on the IFB interface
            # In practice, you'd need IP-based filtering here

            # Store the limit
            self._limits[normalized_mac] = BandwidthLimit(
                mac_address=normalized_mac,
                download_kbps=download_kbps,
                upload_kbps=upload_kbps,
                class_id=class_id
            )

            logger.info(
                f"Set bandwidth limit for {normalized_mac}: "
                f"↓{download_kbps}kbps ↑{upload_kbps}kbps"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to set bandwidth limit: {e}")
            return False

    async def remove_bandwidth_limit(self, mac: str) -> bool:
        """Remove bandwidth limit for a device."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._limits:
            return False

        limit = self._limits[normalized_mac]
        class_id = limit.class_id

        try:
            # Remove tc filter
            await self._run_tc([
                "filter", "del", "dev", self.interface,
                "parent", "1:", "protocol", "ip",
                "handle", str(class_id), "fw"
            ])

            # Remove tc classes
            await self._run_tc([
                "class", "del", "dev", self.interface,
                "parent", "1:1", "classid", f"1:{class_id}"
            ])

            await self._run_tc([
                "class", "del", "dev", self.ifb_interface,
                "parent", "1:1", "classid", f"1:{class_id}"
            ])

            # Remove iptables rule
            await self._runner.run([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-m", "mac", "--mac-source", normalized_mac,
                "-j", "MARK", "--set-mark", str(class_id)
            ])

            self._limits.pop(normalized_mac)
            logger.info(f"Removed bandwidth limit for {normalized_mac}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove bandwidth limit: {e}")
            return False

    async def get_bandwidth_limit(self, mac: str) -> Optional[BandwidthLimit]:
        """Get current bandwidth limit for a device."""
        normalized_mac = normalize_mac(mac)
        return self._limits.get(normalized_mac)

    async def get_all_limits(self) -> Dict[str, BandwidthLimit]:
        """Get all bandwidth limits."""
        return self._limits.copy()

    async def shutdown(self):
        """Clean up all tc configuration."""
        logger.info("Shutting down traffic controller")
        await self._cleanup()
        self._limits.clear()
        self._initialized = False


class BandwidthMonitor:
    """Monitor bandwidth usage per device."""

    def __init__(self, interface: str):
        self.interface = interface
        self._usage: Dict[str, Dict[str, int]] = {}  # MAC -> {bytes_sent, bytes_recv}

    async def get_device_usage(self, mac: str) -> Dict[str, int]:
        """
        Get bandwidth usage for a device.

        Note: This is a simplified implementation. For accurate per-device
        bandwidth monitoring, you'd use iptables accounting rules or
        parse /proc/net/xt_quota/*.
        """
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._usage:
            self._usage[normalized_mac] = {"bytes_sent": 0, "bytes_received": 0}

        return self._usage[normalized_mac]

    async def update_usage(self, mac: str, bytes_sent: int, bytes_received: int):
        """Update usage counters for a device."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._usage:
            self._usage[normalized_mac] = {"bytes_sent": 0, "bytes_received": 0}

        self._usage[normalized_mac]["bytes_sent"] += bytes_sent
        self._usage[normalized_mac]["bytes_received"] += bytes_received
