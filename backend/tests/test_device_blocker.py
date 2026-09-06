import pytest

from core.device_blocker import DeviceBlocker
from utils.commands import CommandError, CommandResult


class FailingRunner:
    async def run(self, argv, **kwargs):
        raise CommandError(argv[0], CommandResult(4, "", "permission denied"))


@pytest.mark.asyncio
async def test_failed_removal_keeps_applied_block_tracked():
    blocker = DeviceBlocker("eth0", runner=FailingRunner())
    blocker._blocked_macs.add("AA:BB:CC:DD:EE:FF")
    assert await blocker.unblock_device("aa:bb:cc:dd:ee:ff") is False
    assert blocker.is_blocked("AA:BB:CC:DD:EE:FF")


@pytest.mark.asyncio
async def test_failed_initialization_does_not_claim_ready():
    blocker = DeviceBlocker("eth0", runner=FailingRunner())
    with pytest.raises(CommandError):
        await blocker.initialize()
    assert not blocker._initialized


class ScriptedRunner:
    def __init__(self, codes):
        self.codes = iter(codes)
        self.calls = []

    async def run(self, argv, *, check=True):
        self.calls.append(argv)
        result = CommandResult(next(self.codes), "", "")
        if check and result.returncode:
            raise CommandError(argv[0], result)
        return result


@pytest.mark.asyncio
async def test_probe_permission_error_is_not_treated_as_missing_chain():
    runner = ScriptedRunner([4])
    blocker = DeviceBlocker("eth0", runner=runner)
    with pytest.raises(CommandError):
        await blocker.initialize()
    assert len(runner.calls) == 1
    assert not blocker._initialized


@pytest.mark.asyncio
async def test_initialization_preserves_existing_chain_and_checks_hook_creation():
    runner = ScriptedRunner([0, 1, 4])
    blocker = DeviceBlocker("eth0", runner=runner)
    with pytest.raises(CommandError):
        await blocker.initialize()
    assert not blocker._initialized
    assert all("-F" not in call for call in runner.calls)


@pytest.mark.asyncio
async def test_successful_block_and_removal_update_tracking():
    runner = ScriptedRunner([0, 0, 0, 0, 0])
    blocker = DeviceBlocker("eth0", runner=runner)
    assert await blocker.block_device("aa:bb:cc:dd:ee:ff")
    assert blocker.is_blocked("aa:bb:cc:dd:ee:ff")
    assert await blocker.unblock_device("aa:bb:cc:dd:ee:ff")
    assert not blocker.is_blocked("aa:bb:cc:dd:ee:ff")


@pytest.mark.asyncio
async def test_shutdown_failure_retains_state_and_does_not_flush_chain():
    runner = ScriptedRunner([4])
    blocker = DeviceBlocker("eth0", runner=runner)
    blocker._initialized = True
    blocker._blocked_macs.add("AA:BB:CC:DD:EE:FF")
    with pytest.raises(RuntimeError, match="Failed to remove device blocks"):
        await blocker.shutdown()
    assert blocker._initialized
    assert blocker.is_blocked("AA:BB:CC:DD:EE:FF")
    assert all("-F" not in call for call in runner.calls)
