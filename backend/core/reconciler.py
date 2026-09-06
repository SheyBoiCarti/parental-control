"""Serialize desired device intent into verified network enforcement state."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from db.models import Device, DeviceEnforcement
from utils.mac_utils import normalize_mac


COMPONENTS = ("interception", "blocking", "content", "bandwidth")


@dataclass(frozen=True)
class EnforcementStatus:
    state: str
    last_error: str | None
    updated_at: str

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "last_error": self.last_error,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class ReconcileResult:
    state: str
    components: dict[str, EnforcementStatus]

    def to_dict(self) -> dict:
        states = {name: status.to_dict() for name, status in self.components.items()}
        updated = max(status.updated_at for status in self.components.values())
        errors = [status.last_error for status in self.components.values() if status.last_error]
        return {
            "state": self.state,
            "last_error": errors[0] if errors else None,
            "updated_at": updated,
            "components": states,
        }


class EnforcementReconciler:
    """Apply and record one device at a time, with a lock per canonical MAC."""

    def __init__(self, sessions: Callable, arp_spoofer, device_blocker, traffic_controller, content_enforcer=None):
        self._sessions = sessions
        self._arp = arp_spoofer
        self._blocker = device_blocker
        self._traffic = traffic_controller
        self._content = content_enforcer
        self._locks: dict[str, asyncio.Lock] = {}

    async def reconcile(self, mac: str) -> ReconcileResult:
        normalized_mac = normalize_mac(mac)
        lock = self._locks.setdefault(normalized_mac, asyncio.Lock())
        async with lock:
            return await self._reconcile_locked(normalized_mac)

    async def reset_runtime_state(self) -> None:
        """Invalidate every result before startup re-verifies kernel state."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with self._sessions() as session:
            await session.execute(
                update(DeviceEnforcement).values(
                    state="pending", last_error=None, updated_at=now
                )
            )

    async def reconcile_all(self) -> dict[str, ReconcileResult]:
        """Replay every persisted device intent during startup or recovery."""
        async with self._sessions() as session:
            macs = list((await session.execute(select(Device.mac_address))).scalars())
        results = {}
        for mac in macs:
            results[mac] = await self.reconcile(mac)
        return results

    async def get_status(self, mac: str) -> ReconcileResult:
        """Read the latest recorded result without touching network state."""
        normalized_mac = normalize_mac(mac)
        async with self._sessions() as session:
            device_id = (
                await session.execute(
                    select(Device.id).where(Device.mac_address == normalized_mac)
                )
            ).scalar_one_or_none()
            if device_id is None:
                raise KeyError(normalized_mac)
            records = {
                record.component: record
                for record in (
                    await session.execute(
                        select(DeviceEnforcement).where(
                            DeviceEnforcement.device_id == device_id
                        )
                    )
                ).scalars()
            }
        fallback = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        statuses = {}
        for component in COMPONENTS:
            record = records.get(component)
            if record is None:
                statuses[component] = EnforcementStatus("pending", None, fallback)
            else:
                timestamp = record.updated_at.replace(tzinfo=timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                )
                statuses[component] = EnforcementStatus(
                    record.state, record.last_error, timestamp
                )
        return ReconcileResult(self._aggregate(statuses), statuses)

    @staticmethod
    def _aggregate(statuses: dict[str, EnforcementStatus]) -> str:
        if any(value.state == "error" for value in statuses.values()):
            return "error"
        if any(value.state == "pending" for value in statuses.values()):
            return "pending"
        if any(value.state == "applied" for value in statuses.values()):
            return "applied"
        return "inactive"

    async def _reconcile_locked(self, mac: str) -> ReconcileResult:
        async with self._sessions() as session:
            device = (
                await session.execute(
                    select(Device)
                    .options(selectinload(Device.rules))
                    .where(Device.mac_address == mac)
                )
            ).scalar_one_or_none()
        if device is None:
            raise KeyError(mac)

        rules = [rule for rule in device.rules if rule.is_active and not rule.validation_error]
        bandwidth_rule = next((rule for rule in rules if rule.rule_type == "bandwidth"), None)
        has_content = any(rule.rule_type in {"block_app", "block_domain"} for rule in rules)
        desired = {
            "blocking": bool(device.is_blocked),
            "content": has_content,
            "bandwidth": bandwidth_rule is not None,
        }
        desired["interception"] = bool(device.is_monitored or any(desired.values()))

        if desired["interception"] and not device.ip_address:
            states = {
                name: ("pending", None) if wanted else ("inactive", None)
                for name, wanted in desired.items()
            }
            return await self._save(device.id, states)

        states = {name: ("inactive", None) for name in COMPONENTS}
        if not desired["interception"]:
            self._arp.remove_target(mac)
            if self._blocker.is_blocked(mac):
                if not await self._blocker.unblock_device(mac):
                    states["blocking"] = ("error", "Block removal failed")
            await self._traffic.remove_bandwidth_limit(mac)
            return await self._save(device.id, states)

        try:
            self._arp.validate_target(device.ip_address, mac)
        except (ValueError, RuntimeError):
            states.update({
                name: ("error", "Device cannot be intercepted") if wanted else ("inactive", None)
                for name, wanted in desired.items()
            })
            return await self._save(device.id, states)

        enforcement_error = None
        if desired["blocking"]:
            if await self._blocker.block_device(mac):
                await self._traffic.remove_bandwidth_limit(mac)
                states["blocking"] = ("applied", None)
                if desired["content"]:
                    states["content"] = ("applied", None)
                if desired["bandwidth"]:
                    states["bandwidth"] = ("applied", None)
            else:
                states["blocking"] = ("error", "Device block application failed")
                enforcement_error = "Device block application failed"
        else:
            if self._blocker.is_blocked(mac) and not await self._blocker.unblock_device(mac):
                states["blocking"] = ("error", "Block removal failed")
                enforcement_error = "Block removal failed"

            if desired["content"]:
                if self._content is None:
                    states["content"] = ("error", "Content enforcement unavailable")
                    enforcement_error = enforcement_error or "Content enforcement unavailable"
                else:
                    try:
                        applied = await self._content.apply_device(mac, device.ip_address, rules)
                    except Exception:
                        applied = False
                    states["content"] = (
                        ("applied", None) if applied else ("error", "Content application failed")
                    )
                    if not applied:
                        enforcement_error = enforcement_error or "Content application failed"

            if desired["bandwidth"]:
                value = bandwidth_rule.rule_value
                applied = await self._traffic.set_bandwidth_limit(
                    mac,
                    value["download_kbps"],
                    value["upload_kbps"],
                    ip_address=device.ip_address,
                )
                states["bandwidth"] = (
                    ("applied", None) if applied else ("error", "Bandwidth application failed")
                )
                if not applied:
                    enforcement_error = enforcement_error or "Bandwidth application failed"
            else:
                await self._traffic.remove_bandwidth_limit(mac)

        if enforcement_error:
            states["interception"] = ("error", enforcement_error)
        else:
            try:
                targets = self._arp.active_targets
                if mac in targets:
                    await self._arp.update_target_ip(mac, device.ip_address)
                else:
                    self._arp.add_target(device.ip_address, mac)
                states["interception"] = ("applied", None)
            except Exception:
                states["interception"] = ("error", "Interception application failed")

        return await self._save(device.id, states)

    async def _save(self, device_id: int, states: dict[str, tuple[str, str | None]]) -> ReconcileResult:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        timestamp = now.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        async with self._sessions() as session:
            existing = {
                record.component: record
                for record in (
                    await session.execute(
                        select(DeviceEnforcement).where(DeviceEnforcement.device_id == device_id)
                    )
                ).scalars()
            }
            for component in COMPONENTS:
                state, error = states[component]
                record = existing.get(component)
                if record is None:
                    session.add(DeviceEnforcement(
                        device_id=device_id,
                        component=component,
                        state=state,
                        last_error=error,
                        updated_at=now,
                    ))
                else:
                    record.state = state
                    record.last_error = error
                    record.updated_at = now
        statuses = {
            component: EnforcementStatus(state, error, timestamp)
            for component, (state, error) in states.items()
        }
        return ReconcileResult(self._aggregate(statuses), statuses)
