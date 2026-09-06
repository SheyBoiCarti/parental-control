"""Bounded worker-thread event delivery to an asynchronous persistence sink."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from queue import Queue, Empty, Full
from threading import Lock
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BatchResult:
    persisted: int
    lost: int = 0
    broadcast_failed: int = 0


async def persist_events(events):
    from sqlalchemy import select
    from sqlalchemy.dialects.sqlite import insert
    from db.database import get_session
    from db.models import AccessLog, Device
    from api.websocket import ws_manager
    inserted = []
    lost = 0
    async with get_session() as session:
        devices = {d.mac_address: d.id for d in (await session.execute(
            select(Device).where(Device.mac_address.in_({e.mac for e in events}))
        )).scalars()}
        for event in events:
            if event.mac not in devices:
                lost += 1
                continue
            result = await session.execute(insert(AccessLog).values(
                event_id=event.event_id, device_id=devices[event.mac], domain=event.domain,
                action=event.action, app_name=event.app_name, timestamp=event.timestamp,
            ).on_conflict_do_nothing(index_elements=["event_id"]).returning(AccessLog.id))
            if result.scalar_one_or_none() is not None:
                inserted.append(event)
    broadcast_failed = 0
    for event in inserted:
        try:
            await ws_manager.broadcast_access_log({
                "event_id": event.event_id, "mac": event.mac, "domain": event.domain,
                "action": event.action, "app": event.app_name,
            })
        except Exception:
            broadcast_failed += 1
            logger.exception("Persisted event notification failed")
    return BatchResult(len(events) - lost, lost, broadcast_failed)


@dataclass(frozen=True)
class AccessEvent:
    mac: str
    domain: str
    action: str
    app_name: str | None = None
    event_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class EventWorker:
    def __init__(self, sink, *, capacity=10000, batch_size=100, flush_seconds=1.0):
        if capacity < 1 or batch_size < 1 or flush_seconds <= 0:
            raise ValueError("Event queue settings must be positive")
        self._queue = Queue(maxsize=capacity)
        self._sink = sink
        self._batch_size = batch_size
        self._flush_seconds = flush_seconds
        self._lock = Lock()
        self._accepting = False
        self._lost = 0
        self._persisted = 0
        self._retries = 0
        self._broadcast_failed = 0
        self._task = None
        self._inflight = 0

    async def start(self):
        if self._task is not None:
            raise RuntimeError("Event worker is already started")
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self._accepting = True
        self._task = asyncio.create_task(self._consume(), name="packet-event-writer")

    def submit(self, event: AccessEvent) -> bool:
        with self._lock:
            if not self._accepting:
                self._lost += 1
                return False
            try:
                self._queue.put_nowait(event)
            except Full:
                self._lost += 1
                return False
            self._loop.call_soon_threadsafe(self._wake.set)
            return True

    def stats(self):
        with self._lock:
            return {"queued": self._queue.qsize(), "inflight": self._inflight,
                    "lost": self._lost, "persisted": self._persisted, "retries": self._retries,
                    "broadcast_failed": self._broadcast_failed}

    async def _consume(self):
        while self._accepting or not self._queue.empty():
            batch = []
            deadline = self._loop.time() + self._flush_seconds
            while len(batch) < self._batch_size:
                self._wake.clear()
                try:
                    batch.append(self._queue.get_nowait())
                    continue
                except Empty:
                    pass
                if not self._accepting or self._loop.time() >= deadline:
                    break
                try:
                    await asyncio.wait_for(self._wake.wait(), deadline - self._loop.time())
                except TimeoutError:
                    break
            if not batch:
                continue
            self._inflight = len(batch)
            for attempt in range(3):
                try:
                    result = await self._sink(tuple(batch))
                    with self._lock:
                        self._persisted += result.persisted if result is not None else len(batch)
                        if result is not None:
                            self._lost += result.lost
                            self._broadcast_failed += result.broadcast_failed
                    break
                except Exception:
                    logger.exception("Packet event batch persistence failed")
                    with self._lock:
                        if attempt == 2:
                            self._lost += len(batch)
                        else:
                            self._retries += 1
                    if attempt < 2:
                        await asyncio.sleep(0.05 * (attempt + 1))
            self._inflight = 0

    async def stop(self):
        if self._task is None:
            return
        with self._lock:
            self._accepting = False
        self._wake.set()
        try:
            await asyncio.wait_for(self._task, 10)
        except TimeoutError:
            with self._lock:
                self._lost += self._inflight + self._queue.qsize()
                self._inflight = 0
                while not self._queue.empty():
                    self._queue.get_nowait()
            raise RuntimeError("Packet event drain timed out")
        finally:
            self._task = None
