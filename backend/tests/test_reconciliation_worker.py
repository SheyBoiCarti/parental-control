import asyncio

import pytest


@pytest.mark.asyncio
async def test_reconciliation_worker_retries_after_failure_until_success():
    from core.reconciliation_worker import ReconciliationWorker

    recovered = asyncio.Event()

    class Reconciler:
        def __init__(self):
            self.calls = 0

        async def reconcile_all(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary reconciliation failure")
            recovered.set()
            return {"AA:BB:CC:DD:EE:01": object()}

    reconciler = Reconciler()
    worker = ReconciliationWorker(reconciler, interval_seconds=0.01)

    await worker.start()
    await asyncio.wait_for(recovered.wait(), timeout=0.2)
    await worker.stop()

    assert reconciler.calls >= 2
    assert worker.stats()["runs"] >= 1
    assert worker.stats()["failures"] == 1


@pytest.mark.asyncio
async def test_reconciliation_worker_retains_stalled_task_until_it_terminates():
    from core.reconciliation_worker import ReconciliationWorker

    started = asyncio.Event()
    release = asyncio.Event()
    cancellation_seen = asyncio.Event()

    class Reconciler:
        async def reconcile_all(self):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await release.wait()

    worker = ReconciliationWorker(Reconciler(), interval_seconds=0.001)
    await worker.start()
    await asyncio.wait_for(started.wait(), timeout=0.1)
    task = worker._task

    stopping = asyncio.create_task(worker.stop(timeout=0.01))
    await asyncio.wait_for(cancellation_seen.wait(), timeout=0.1)
    await asyncio.sleep(0.02)
    try:
        assert stopping.done()
        assert worker._task is not None
        assert not worker._task.done()
        with pytest.raises(RuntimeError, match="already started"):
            await worker.start()
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(stopping, return_exceptions=True), timeout=0.1)

    with pytest.raises(RuntimeError, match="did not stop"):
        await stopping
    assert task is not None
    await asyncio.wait_for(task, timeout=0.1)
    await worker.stop(timeout=0.01)
    assert worker._task is None
