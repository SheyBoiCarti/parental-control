import pytest
from core.traffic_controller import TrafficController, BandwidthLimit
from utils.commands import CommandError, CommandResult


class FailedRunner:
    async def run(self, argv, **kwargs):
        raise CommandError(argv[0], CommandResult(4, "", "denied"))


@pytest.mark.asyncio
async def test_failed_limit_removal_preserves_tracking():
    controller = TrafficController("eth0", runner=FailedRunner())
    mac = "AA:BB:CC:DD:EE:01"
    controller._limits[mac] = BandwidthLimit(mac, 1000, 500, 10)
    assert await controller.remove_bandwidth_limit(mac) is False
    assert await controller.get_bandwidth_limit(mac) is not None


@pytest.mark.asyncio
async def test_tc_failure_is_propagated_to_caller():
    controller = TrafficController("eth0", runner=FailedRunner())
    with pytest.raises(CommandError):
        await controller._run_tc(["qdisc", "show"])


@pytest.mark.asyncio
async def test_mark_cleanup_only_deletes_tracked_rule_specs():
    calls = []
    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            return CommandResult(0, "1 MARK all -- anywhere anywhere MARK set 0x99", "")
    controller = TrafficController("eth0", runner=Runner())
    mac = "AA:BB:CC:DD:EE:01"
    controller._limits[mac] = BandwidthLimit(mac, 1000, 500, 10)
    await controller._cleanup_iptables_marks()
    assert calls == [["iptables", "-t", "mangle", "-D", "PREROUTING",
                      "-m", "mac", "--mac-source", mac,
                      "-j", "MARK", "--set-mark", "10"]]
