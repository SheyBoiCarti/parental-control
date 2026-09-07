"""Persist deltas from owned traffic-control byte counters."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import inspect
import logging
import time
from typing import Callable

from sqlalchemy import delete, select

from db.models import AccessLog, BandwidthLog, Device


logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class BandwidthMonitor:
    """Poll tc class totals and persist nonnegative per-device deltas."""

    def __init__(
        self,
        controller,
        sessions: Callable,
        broadcaster: Callable,
        *,
        interval_seconds: float = 5,
        retention_days: int = 30,
        prune_interval_seconds: float = 3600,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._controller = controller
        self._sessions = sessions
        self._broadcaster = broadcaster
        self._interval = interval_seconds
        self._retention_days = retention_days
        self._prune_interval = prune_interval_seconds
        self._clock = clock
        self._monotonic = monotonic
        self._baselines: dict[str, tuple[tuple[str, int], int, int]] = {}
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._poll_failures = 0
        self._prune_failures = 0
        self._broadcast_failures = 0
        self._persisted_samples = 0

    def stats(self) -> dict[str, int]:
        return {
            "poll_failures": self._poll_failures,
            "prune_failures": self._prune_failures,
            "broadcast_failures": self._broadcast_failures,
            "persisted_samples": self._persisted_samples,
        }

    async def poll_once(self) -> int:
        counters = await self._controller.read_bandwidth_counters()
        now = self._clock()
        pending: list[tuple[str, int, int, tuple[tuple[str, int], int, int]]] = []
        active_macs = set(counters)
        for mac in list(self._baselines):
            if mac not in active_macs:
                self._baselines.pop(mac, None)

        for mac, current in counters.items():
            identity = (str(current["ip_address"]), int(current["class_id"]))
            sent = int(current["bytes_sent"])
            received = int(current["bytes_received"])
            previous = self._baselines.get(mac)
            current_baseline = (identity, sent, received)
            if previous is None or previous[0] != identity:
                self._baselines[mac] = current_baseline
                continue
            delta_sent = sent - previous[1] if sent >= previous[1] else 0
            delta_received = received - previous[2] if received >= previous[2] else 0
            if delta_sent or delta_received:
                pending.append((mac, delta_sent, delta_received, current_baseline))
            else:
                self._baselines[mac] = current_baseline

        if not pending:
            return 0

        async with self._sessions() as session:
            result = await session.execute(
                select(Device).where(Device.mac_address.in_([row[0] for row in pending]))
            )
            devices = {device.mac_address: device for device in result.scalars()}
            persisted = []
            for mac, sent, received, current_baseline in pending:
                device = devices.get(mac)
                if device is None:
                    logger.warning("Skipping bandwidth sample for unknown device %s", mac)
                    self._baselines[mac] = current_baseline
                    continue
                session.add(BandwidthLog(
                    device_id=device.id,
                    timestamp=now,
                    bytes_sent=sent,
                    bytes_received=received,
                ))
                persisted.append((mac, sent, received, current_baseline))

        self._persisted_samples += len(persisted)
        for mac, sent, received, current_baseline in persisted:
            self._baselines[mac] = current_baseline
            payload = {
                "mac_address": mac,
                "timestamp": now.isoformat(),
                "bytes_sent": sent,
                "bytes_received": received,
            }
            try:
                outcome = self._broadcaster(payload)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception:
                self._broadcast_failures += 1
                logger.exception("Failed to broadcast committed bandwidth sample")
        return len(persisted)

    async def prune_once(self) -> int:
        cutoff = self._clock() - timedelta(days=self._retention_days)
        async with self._sessions() as session:
            bandwidth = await session.execute(
                delete(BandwidthLog).where(BandwidthLog.timestamp < cutoff)
            )
            access = await session.execute(
                delete(AccessLog).where(AccessLog.timestamp < cutoff)
            )
        return int(bandwidth.rowcount or 0) + int(access.rowcount or 0)

    async def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("Bandwidth monitor is already started")
        self._stop.clear()

        async def run() -> None:
            next_prune = self._monotonic()
            while not self._stop.is_set():
                try:
                    await self.poll_once()
                except Exception:
                    self._poll_failures += 1
                    logger.exception("Bandwidth counter poll failed")
                if self._monotonic() >= next_prune:
                    try:
                        await self.prune_once()
                    except Exception:
                        self._prune_failures += 1
                        logger.exception("Telemetry retention prune failed")
                    next_prune = self._monotonic() + self._prune_interval
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass

        task = asyncio.create_task(run(), name="bandwidth-monitor")
        self._task = task
        task.add_done_callback(self._clear_finished_task)

    def _clear_finished_task(self, task: asyncio.Task) -> None:
        if self._task is task:
            self._task = None
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

    async def stop(self, timeout: float = 2.0) -> None:
        if self._task is None:
            return
        self._stop.set()
        task = self._task
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except TimeoutError as error:
            task.cancel()
            await asyncio.sleep(0)
            raise RuntimeError("Bandwidth monitor did not stop") from error
        finally:
            if task.done() and self._task is task:
                self._task = None
