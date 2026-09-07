import asyncio
import threading
import pytest
from core.packet_analyzer import PacketAnalyzer


@pytest.mark.asyncio
async def test_quiet_capture_exits_and_is_joined_before_stop_returns(monkeypatch):
    entered = threading.Event()
    exited = threading.Event()
    release = threading.Event()
    def quiet_sniff(**kwargs):
        entered.set()
        release.wait(kwargs.get("timeout", 5))
        exited.set()
    monkeypatch.setattr("core.packet_analyzer.sniff", quiet_sniff)
    analyzer = PacketAnalyzer("eth0")
    try:
        await analyzer.start()
        assert await asyncio.to_thread(entered.wait, 1)
        task = analyzer._sniff_task
        await asyncio.wait_for(analyzer.stop(), 2)
        assert exited.is_set()
        assert task.done()
        assert not analyzer.get_stats()["running"]
    finally:
        release.set()


@pytest.mark.asyncio
async def test_capture_failure_is_reported_and_not_left_running(monkeypatch):
    def fail(**kwargs):
        raise OSError("capture unavailable")
    monkeypatch.setattr("core.packet_analyzer.sniff", fail)
    analyzer = PacketAnalyzer("eth0")
    await analyzer.start()
    await asyncio.sleep(0.05)
    assert not analyzer.get_stats()["running"]
    with pytest.raises(OSError):
        await analyzer.stop()
