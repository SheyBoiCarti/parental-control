"""Traffic controller using Linux tc for bandwidth limiting."""

import asyncio
import logging
import json
import os
import re
import ipaddress
from pathlib import Path
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

    def __init__(self, interface: str, *, runner=None, ownership_file: Path | None = None):
        self._runner = runner if runner is not None else CommandRunner()
        self.interface = interface
        self._limits: Dict[str, BandwidthLimit] = {}  # MAC -> BandwidthLimit
        self._next_class_id = 10
        self._initialized = False
        self._owned_qdiscs = []
        self._pending_removals: Dict[str, list[tuple[str, int]]] = {}
        self._ownership_file = ownership_file

    def set_ownership_file(self, path: Path) -> None:
        if self._initialized:
            raise RuntimeError("Cannot change traffic-control ownership after initialization")
        self._ownership_file = path

    async def initialize(self):
        """Initialize tc qdisc and classes."""
        if self._initialized:
            return

        logger.info("Initializing traffic controller")

        # Clean up any existing configuration
        await self._cleanup()

        if await self._assert_available(self.interface):
            self._owned_qdiscs.append((self.interface, "root", "1:", "htb"))
            self._initialized = True
            logger.info("Recovered owned traffic controller")
            return

        try:
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

            self._record_ownership()
        except BaseException:
            try:
                await self._cleanup()
            except Exception:
                logger.exception("Failed to roll back traffic-control initialization")
            raise
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

    async def _classes(self, interface):
        result = await self._runner.run(["tc", "-j", "class", "show", "dev", interface])
        try:
            values = json.loads(result.stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Cannot inspect existing traffic control classes") from error
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise RuntimeError("Cannot inspect existing traffic control classes")
        return values

    def _owns_root(self) -> bool:
        if self._ownership_file is None:
            return False
        try:
            record = json.loads(self._ownership_file.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return False
        return record == {"interface": self.interface, "handle": "1:", "kind": "htb"}

    def _record_ownership(self) -> None:
        if self._ownership_file is None:
            return
        self._ownership_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._ownership_file.with_suffix(self._ownership_file.suffix + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"interface": self.interface, "handle": "1:", "kind": "htb"}, output)
        os.replace(temporary, self._ownership_file)
        self._ownership_file.chmod(0o600)

    def _forget_ownership(self) -> None:
        if self._ownership_file is not None:
            self._ownership_file.unlink(missing_ok=True)

    async def _assert_available(self, interface) -> bool:
        qdiscs = []
        for qdisc in await self._qdiscs(interface):
            if qdisc.get("kind") == "noqueue" and qdisc.get("handle") == "0:":
                continue
            qdiscs.append(qdisc)
        if not qdiscs:
            self._forget_ownership()
            return False
        if len(qdiscs) == 1 and qdiscs[0].get("kind") == "htb" and qdiscs[0].get("handle") == "1:":
            options = qdiscs[0].get("options", {})
            default = options.get("default") if isinstance(options, dict) else None
            classids = {item.get("classid") or item.get("handle") for item in await self._classes(interface)}
            if (
                self._owns_root()
                and str(default) == "9999"
                and {"1:1", "1:9999"}.issubset(classids)
            ):
                return True
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
                if interface == self.interface and handle == "1:" and kind == "htb":
                    self._forget_ownership()
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
        if normalized_mac in self._pending_removals and not await self.remove_bandwidth_limit(normalized_mac):
            return False
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
            return True
        resources = self._pending_removals.setdefault(
            normalized_mac,
            [
                (kind, identifier)
                for identifier in (limit.class_id, limit.class_id + 1)
                for kind in ("filter", "class")
            ],
        )
        try:
            while resources:
                resource_type, identifier = resources[0]
                if resource_type == "filter":
                    await self._run_tc([
                        "filter", "del", "dev", self.interface, "parent", "1:",
                        "protocol", "ip", "pref", str(identifier), "handle", str(identifier), "flower",
                    ])
                else:
                    await self._run_tc([
                        "class", "del", "dev", self.interface, "parent", "1:1",
                        "classid", f"1:{identifier:x}",
                    ])
                resources.pop(0)
            self._limits.pop(normalized_mac)
            self._pending_removals.pop(normalized_mac, None)
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
        by_handle: dict[str, int] = {}
        parsed_ok = False
        try:
            inventory = json.loads(result.stdout)
            if isinstance(inventory, list):
                for item in inventory:
                    if not isinstance(item, dict):
                        continue
                    handle = item.get("handle") or item.get("classid")
                    stats = item.get("stats")
                    if not isinstance(handle, str) or not isinstance(stats, dict):
                        continue
                    byte_count = stats.get("bytes")
                    if type(byte_count) is int and byte_count >= 0:
                        by_handle[handle.lower()] = byte_count
                parsed_ok = True
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

        if not parsed_ok:
            for match in re.finditer(
                r"class\s+\w+\s+([0-9a-fA-F:]+).*?\n\s*Sent\s+(\d+)\s+bytes",
                result.stdout,
                re.IGNORECASE,
            ):
                handle = match.group(1).lower()
                by_handle[handle] = int(match.group(2))
                parsed_ok = True

        if not parsed_ok and self._limits:
            raise RuntimeError("Cannot read traffic accounting counters")

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
