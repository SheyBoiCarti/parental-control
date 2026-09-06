"""Owned iptables rules and NFQUEUE lifecycle for inline content enforcement."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shlex

from utils.commands import CommandError, CommandRunner
from utils.mac_utils import normalize_mac


logger = logging.getLogger(__name__)


class ContentEnforcer:
    def __init__(self, interface, inspector, *, runner=None, worker):
        self.interface = interface
        self._inspector = inspector
        self._runner = runner if runner is not None else CommandRunner()
        self._worker = worker
        self._chain = "PARENTAL_CONTENT"
        self._hook_comment = "parental-control:content-hook"
        self._initialized = False
        self._created_chain = False
        self._created_hook = False
        self._devices: dict[str, tuple[str, tuple, list[list[str]]]] = {}

    @property
    def _hook(self) -> list[str]:
        return [
            "-m", "comment", "--comment", self._hook_comment,
            "-j", self._chain,
        ]

    async def initialize(self) -> None:
        if self._initialized:
            return
        inventory = await self._runner.run(
            ["iptables", "-S", self._chain], check=False
        )
        stale_specs = []
        if inventory.returncode == 0:
            lines = [line for line in inventory.stdout.splitlines() if line.strip()]
            for line in lines:
                tokens = shlex.split(line)
                if tokens == ["-N", self._chain]:
                    continue
                try:
                    comment = tokens[tokens.index("--comment") + 1]
                except (ValueError, IndexError):
                    comment = ""
                if tokens[:2] != ["-A", self._chain] or not comment.startswith(
                    "parental-control:content:"
                ):
                    raise RuntimeError("Content chain contains foreign rules; startup refused")
                stale_specs.append(tokens[2:])
        elif inventory.returncode != 1:
            raise CommandError("iptables", inventory)

        self._worker.start()
        try:
            if inventory.returncode == 1:
                await self._runner.run(["iptables", "-N", self._chain])
                self._created_chain = True
            else:
                self._created_chain = True
                for spec in reversed(stale_specs):
                    await self._runner.run(["iptables", "-D", self._chain, *spec])
            hook = await self._runner.run(
                ["iptables", "-C", "FORWARD", *self._hook], check=False
            )
            if hook.returncode == 1:
                await self._runner.run([
                    "iptables", "-I", "FORWARD", "1", *self._hook
                ])
                self._created_hook = True
            elif hook.returncode == 0:
                self._created_hook = True
            elif hook.returncode:
                raise CommandError("iptables", hook)
            self._initialized = True
        except BaseException:
            await self._rollback_initialize()
            raise

    async def _rollback_initialize(self) -> None:
        failures = []
        if self._created_hook:
            try:
                await self._runner.run(["iptables", "-D", "FORWARD", *self._hook])
                self._created_hook = False
            except Exception as error:
                failures.append(error)
        if self._created_chain:
            try:
                await self._runner.run(["iptables", "-X", self._chain])
                self._created_chain = False
            except Exception as error:
                failures.append(error)
        try:
            await asyncio.to_thread(self._worker.stop)
        except Exception as error:
            failures.append(error)
        if failures:
            raise ExceptionGroup("Content enforcement startup rollback failed", failures)

    @staticmethod
    def _fingerprint(rules) -> tuple:
        values = []
        for rule in rules:
            if getattr(rule, "rule_type", None) not in {
                "block_app",
                "block_domain",
            }:
                continue
            values.append((
                getattr(rule, "id", None),
                getattr(rule, "rule_type", None),
                repr(getattr(rule, "rule_value", None)),
                bool(getattr(rule, "is_active", True)),
            ))
        return tuple(sorted(values, key=repr))

    def _specs(self, mac: str, ip_address: str) -> list[list[str]]:
        owner = "parental-control:content:" + mac.replace(":", "").lower()
        queue = str(self._worker.queue_number)
        common = ["-s", ip_address, "-m", "comment", "--comment", owner]
        return [
            [*common, "-p", "udp", "--dport", "443", "-j", "DROP"],
            [*common, "-p", "udp", "--dport", "53", "-j", "NFQUEUE", "--queue-num", queue],
            [
                *common, "-p", "tcp", "-m", "multiport", "--dports", "53,443",
                "-j", "NFQUEUE", "--queue-num", queue,
            ],
        ]

    async def apply_device(self, mac: str, ip_address: str, rules) -> bool:
        if not self._initialized:
            await self.initialize()
        if not self._worker.is_healthy:
            logger.error("Content queue worker is unavailable")
            return False
        normalized_mac = normalize_mac(mac)
        address = str(ipaddress.IPv4Address(ip_address))
        fingerprint = self._fingerprint(rules)
        existing = self._devices.get(normalized_mac)
        if existing and existing[:2] == (address, fingerprint):
            return True
        if existing and not await self.remove_device(normalized_mac):
            return False

        specs = self._specs(normalized_mac, address)
        added = []
        self._inspector.set_device(address, normalized_mac)
        try:
            for spec in specs:
                await self._runner.run(["iptables", "-A", self._chain, *spec])
                added.append(spec)
        except Exception:
            logger.exception("Failed to install content queue rules")
            for spec in reversed(added):
                try:
                    await self._runner.run(["iptables", "-D", self._chain, *spec])
                except Exception:
                    logger.exception("Failed to roll back content queue rule")
            self._inspector.remove_device(address)
            return False
        self._devices[normalized_mac] = (address, fingerprint, specs)
        return True

    async def remove_device(self, mac: str) -> bool:
        normalized_mac = normalize_mac(mac)
        existing = self._devices.get(normalized_mac)
        if existing is None:
            return True
        address, _, specs = existing
        try:
            for spec in reversed(specs):
                await self._runner.run(["iptables", "-D", self._chain, *spec])
        except Exception:
            logger.exception("Failed to remove content queue rules")
            return False
        self._devices.pop(normalized_mac, None)
        self._inspector.remove_device(address)
        return True

    async def shutdown(self) -> None:
        failures = []
        for mac in list(self._devices):
            if not await self.remove_device(mac):
                failures.append(RuntimeError(f"Failed to remove content rules for {mac}"))
        if self._created_hook:
            try:
                await self._runner.run(["iptables", "-D", "FORWARD", *self._hook])
                self._created_hook = False
            except Exception as error:
                failures.append(error)
        if self._created_chain:
            try:
                await self._runner.run(["iptables", "-X", self._chain])
                self._created_chain = False
            except Exception as error:
                failures.append(error)
        try:
            await asyncio.to_thread(self._worker.stop)
        except Exception as error:
            failures.append(error)
        self._initialized = False
        if failures:
            raise ExceptionGroup("Content enforcement shutdown failed", failures)
