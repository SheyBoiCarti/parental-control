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
