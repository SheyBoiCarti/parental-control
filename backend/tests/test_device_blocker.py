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
async def test_foreign_rule_in_block_chain_is_preserved_and_startup_refuses():
    class ForeignRunner:
        def __init__(self):
            self.calls = []

        async def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv == ["iptables", "-S", "PARENTAL_BLOCK"]:
                return CommandResult(
                    0,
                    "-N PARENTAL_BLOCK\n-A PARENTAL_BLOCK -j ACCEPT\n",
                    "",
                )
            return CommandResult(0, "", "")

    runner = ForeignRunner()
    blocker = DeviceBlocker("eth0", runner=runner)

    with pytest.raises(RuntimeError, match="foreign rules"):
        await blocker.initialize()

    assert ["iptables", "-F", "PARENTAL_BLOCK"] not in runner.calls
    assert ["iptables", "-X", "PARENTAL_BLOCK"] not in runner.calls


@pytest.mark.asyncio
async def test_restart_reclaims_exact_owned_blocks_and_uses_owned_forward_hook():
    stale = (
        "-N PARENTAL_BLOCK\n"
        "-A PARENTAL_BLOCK -m mac --mac-source AA:BB:CC:DD:EE:21 "
        "-m comment --comment parental-control:block:aabbccddee21 -j DROP\n"
    )

    class Runner:
        def __init__(self):
            self.calls = []

        async def run(self, argv, **kwargs):
            self.calls.append(argv)
            if argv == ["iptables", "-S", "PARENTAL_BLOCK"]:
                return CommandResult(0, stale, "")
            if argv[:4] == ["iptables", "-C", "FORWARD", "-m"]:
                return CommandResult(1, "", "")
            return CommandResult(0, "", "")

    runner = Runner()
    blocker = DeviceBlocker("eth0", runner=runner)
    await blocker.initialize()
    assert await blocker.block_device("AA:BB:CC:DD:EE:22")

    assert [
        "iptables", "-D", "PARENTAL_BLOCK", "-m", "mac", "--mac-source",
        "AA:BB:CC:DD:EE:21", "-m", "comment", "--comment",
        "parental-control:block:aabbccddee21", "-j", "DROP",
    ] in runner.calls
    assert any(
        call[:4] == ["iptables", "-I", "FORWARD", "1"]
        and "parental-control:block-hook" in call
        for call in runner.calls
    )
    assert all("INPUT" not in call for call in runner.calls)
    assert any(
        call[:3] == ["iptables", "-A", "PARENTAL_BLOCK"]
        and "parental-control:block:aabbccddee22" in call
        for call in runner.calls
    )


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
