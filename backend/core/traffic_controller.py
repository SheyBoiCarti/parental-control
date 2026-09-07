"""Traffic controller using Linux tc for bandwidth limiting."""

import asyncio
import logging
import json
import ipaddress
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
    class_id: int       # Upload class; download uses the next class
    ip_address: str | None = None


class TrafficController:
    """
    Controls bandwidth using Linux Traffic Control (tc).

    Uses separate HTB classes and IPv4 flower classifiers on forwarded
    egress traffic: source IP for upload, destination IP for download.
    """

    def __init__(self, interface: str, *, runner=None):
        self._runner = runner if runner is not None else CommandRunner()
        self.interface = interface
        self._limits: Dict[str, BandwidthLimit] = {}  # MAC -> BandwidthLimit
        self._next_class_id = 10
        self._initialized = False
        self._owned_qdiscs = []

    async def initialize(self):
        """Initialize tc qdisc and classes."""
        if self._initialized:
            return

        logger.info("Initializing traffic controller")

        # Clean up any existing configuration
        await self._cleanup()

        await self._assert_available(self.interface)

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

        self._initialized = True
        logger.info("Traffic controller initialized")

    async def _qdiscs(self, interface):
        result = await self._runner.run(["tc", "-j", "qdisc", "show", "dev", interface])
        try:
            values = json.loads(result.stdout)
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise ValueError("Invalid qdisc inventory")
            return values
        except (ValueError, TypeError) as error:
            raise RuntimeError("Cannot inspect existing traffic control") from error

    async def _assert_available(self, interface):
        for qdisc in await self._qdiscs(interface):
            if qdisc.get("kind") == "noqueue" and qdisc.get("handle") == "0:":
                continue
            raise RuntimeError(f"Existing traffic control on {interface} must be preserved")

    async def _cleanup(self):
        """Delete only queues created successfully by this controller instance."""
        failures = []
        for interface, location, handle, kind in reversed(self._owned_qdiscs.copy()):
            try:
                inventory = await self._qdiscs(interface)
                matching = [item for item in inventory if item.get("handle") == handle]
                if matching:
                    if len(matching) != 1 or matching[0].get("kind") != kind:
                        raise RuntimeError("Traffic control ownership changed; cleanup refused")
                    await self._runner.run(["tc", "qdisc", "del", "dev", interface, location, "handle", handle])
                self._owned_qdiscs.remove((interface, location, handle, kind))
            except Exception as error:
                failures.append(error)
        if failures:
            raise ExceptionGroup("Traffic control cleanup failed", failures)

    async def _run_tc(self, args: list, check: bool = True) -> Tuple[int, str, str]:
        """Run tc command."""
        cmd = ["tc"] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        result = await self._runner.run(cmd, check=check)
        if result.returncode == 0 and args[:2] == ["qdisc", "add"]:
            interface = args[args.index("dev") + 1]
            handle = args[args.index("handle") + 1]
            location = "ingress" if "ingress" in args else "root"
            kind = "ingress" if location == "ingress" else "htb"
            self._owned_qdiscs.append((interface, location, handle, kind))
        return result

    def _get_next_class_id(self) -> int:
        """Get next available class ID."""
        class_id = self._next_class_id
        if class_id >= 0x9000:
            raise RuntimeError("Bandwidth class capacity exhausted")
        self._next_class_id += 2
        return class_id

    async def set_bandwidth_limit(
        self, mac: str, download_kbps: int, upload_kbps: int, *, ip_address: str | None = None
    ) -> bool:
        """Apply independent upload/download classes to a known device address."""
        normalized_mac = normalize_mac(mac)
        if ip_address is None:
            raise ValueError("Bandwidth enforcement requires the current device IPv4 address")
        address = str(ipaddress.IPv4Address(ip_address))
        if any(type(rate) is not int or rate < 1 for rate in (download_kbps, upload_kbps)):
            raise ValueError("Bandwidth rates must be positive integers")
        if not self._initialized:
            await self.initialize()
        existing = self._limits.get(normalized_mac)
        class_id = existing.class_id if existing else self._get_next_class_id()
        created_resources = []
        try:
            for offset, direction, rate in ((0, "src_ip", upload_kbps), (1, "dst_ip", download_kbps)):
                identifier = class_id + offset
                classid = f"1:{identifier:x}"
                await self._run_tc([
                    "class", "replace", "dev", self.interface, "parent", "1:1",
                    "classid", classid, "htb", "rate", f"{rate}kbit", "ceil", f"{rate}kbit",
                ])
                created_resources.append(("class", identifier))
                await self._run_tc([
                    "filter", "replace", "dev", self.interface, "parent", "1:",
                    "protocol", "ip", "pref", str(identifier), "handle", str(identifier),
                    "flower", "skip_hw", direction, address + "/32", "classid", classid,
                ])
                created_resources.append(("filter", identifier))
            self._limits[normalized_mac] = BandwidthLimit(
                normalized_mac, download_kbps, upload_kbps, class_id, address
            )
            return True
        except Exception:
            logger.exception("Failed to apply directional bandwidth limit")
            if existing is not None:
                try:
                    for offset, direction, rate in (
                        (0, "src_ip", existing.upload_kbps),
                        (1, "dst_ip", existing.download_kbps),
                    ):
                        identifier = existing.class_id + offset
                        classid = f"1:{identifier:x}"
                        await self._run_tc([
                            "class", "replace", "dev", self.interface, "parent", "1:1",
                            "classid", classid, "htb", "rate", f"{rate}kbit", "ceil", f"{rate}kbit",
                        ])
                        await self._run_tc([
                            "filter", "replace", "dev", self.interface, "parent", "1:",
                            "protocol", "ip", "pref", str(identifier), "handle", str(identifier),
                            "flower", "skip_hw", direction, existing.ip_address + "/32",
                            "classid", classid,
                        ])
                except Exception:
                    logger.exception("Failed to restore previous bandwidth limit")
            else:
                for resource_type, identifier in reversed(created_resources):
                    try:
                        if resource_type == "filter":
                            await self._run_tc([
                                "filter", "del", "dev", self.interface, "parent", "1:",
                                "protocol", "ip", "pref", str(identifier), "handle", str(identifier),
                                "flower",
                            ])
                        else:
                            await self._run_tc([
                                "class", "del", "dev", self.interface, "parent", "1:1",
                                "classid", f"1:{identifier:x}",
                            ])
                    except Exception:
                        logger.exception("Failed to roll back partial bandwidth limit")
            return False

    async def remove_bandwidth_limit(self, mac: str) -> bool:
        normalized_mac = normalize_mac(mac)
        limit = self._limits.get(normalized_mac)
        if limit is None:
            return False
        try:
            for identifier in (limit.class_id, limit.class_id + 1):
                await self._run_tc([
                    "filter", "del", "dev", self.interface, "parent", "1:",
                    "protocol", "ip", "pref", str(identifier), "handle", str(identifier), "flower",
                ])
                await self._run_tc([
                    "class", "del", "dev", self.interface, "parent", "1:1",
                    "classid", f"1:{identifier:x}",
                ])
            self._limits.pop(normalized_mac)
            return True
        except Exception:
            logger.exception("Failed to remove directional bandwidth limit")
            return False

    async def get_bandwidth_limit(self, mac: str) -> Optional[BandwidthLimit]:
        """Get current bandwidth limit for a device."""
        normalized_mac = normalize_mac(mac)
        return self._limits.get(normalized_mac)

    async def get_all_limits(self) -> Dict[str, BandwidthLimit]:
        """Get all bandwidth limits."""
        return self._limits.copy()

    async def read_bandwidth_counters(self) -> Dict[str, Dict[str, int | str]]:
        """Read byte totals for this instance's owned directional classes."""
        result = await self._runner.run([
            "tc", "-j", "-s", "class", "show", "dev", self.interface,
        ])
        try:
            inventory = json.loads(result.stdout)
            if not isinstance(inventory, list):
                raise ValueError
            by_handle = {}
            for item in inventory:
                if not isinstance(item, dict):
                    raise ValueError
                handle = item.get("handle") or item.get("classid")
                stats = item.get("stats")
                if not isinstance(handle, str) or not isinstance(stats, dict):
                    continue
                byte_count = stats.get("bytes")
                if type(byte_count) is not int or byte_count < 0:
                    raise ValueError
                by_handle[handle.lower()] = byte_count
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Cannot read traffic accounting counters") from error

        counters: Dict[str, Dict[str, int | str]] = {}
        for mac, limit in self._limits.items():
            upload_handle = f"1:{limit.class_id:x}"
            download_handle = f"1:{limit.class_id + 1:x}"
            if upload_handle not in by_handle or download_handle not in by_handle:
                raise RuntimeError(f"Owned traffic counters are missing for {mac}")
            counters[mac] = {
                "ip_address": limit.ip_address or "",
                "class_id": limit.class_id,
                "bytes_sent": by_handle[upload_handle],
                "bytes_received": by_handle[download_handle],
            }
        return counters

    async def shutdown(self):
        """Clean up all tc configuration."""
        logger.info("Shutting down traffic controller")
        await self._cleanup()
        self._limits.clear()
        self._initialized = False
