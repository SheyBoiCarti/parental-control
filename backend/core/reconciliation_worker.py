"""Periodic retry supervision for persisted enforcement intent."""

from __future__ import annotations

import asyncio
import logging


logger = logging.getLogger(__name__)


class ReconciliationWorker:
    def __init__(self, reconciler, *, interval_seconds: float = 30.0):
        if interval_seconds <= 0:
            raise ValueError("Reconciliation interval must be positive")
        self._reconciler = reconciler
        self._interval = interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._runs = 0
        self._failures = 0

    def stats(self) -> dict[str, int]:
        return {"runs": self._runs, "failures": self._failures}

    async def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("Reconciliation worker is already started")
        self._stop.clear()

        async def run() -> None:
            while not self._stop.is_set():
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                    continue
                except TimeoutError:
                    pass
                try:
                    await self._reconciler.reconcile_all()
                    self._runs += 1
                except Exception:
                    self._failures += 1
                    logger.exception("Periodic enforcement reconciliation failed")

        task = asyncio.create_task(run(), name="enforcement-reconciliation")
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
            raise RuntimeError("Reconciliation worker did not stop") from error
        finally:
            if task.done() and self._task is task:
                self._task = None
