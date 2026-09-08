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
async def test_removing_an_absent_limit_is_idempotent_success():
    controller = TrafficController("eth0", runner=FailedRunner())
    assert await controller.remove_bandwidth_limit("AA:BB:CC:DD:EE:02") is True


@pytest.mark.asyncio
async def test_tc_failure_is_propagated_to_caller():
    controller = TrafficController("eth0", runner=FailedRunner())
    with pytest.raises(CommandError):
        await controller._run_tc(["qdisc", "show"])


@pytest.mark.asyncio
async def test_foreign_qdisc_blocks_initialization_without_deletion():
    calls = []
    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            return CommandResult(0, '[{"kind":"fq_codel","handle":"8001:","root":true}]', "")
    controller = TrafficController("eth0", runner=Runner())
    with pytest.raises(RuntimeError, match="Existing traffic control"):
        await controller.initialize()
    assert all("del" not in call and "add" not in call for call in calls)
    assert not controller._initialized


@pytest.mark.asyncio
async def test_shutdown_before_initialization_does_not_modify_kernel():
    calls = []
    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            return CommandResult(0, "[]", "")
    await TrafficController("eth0", runner=Runner()).shutdown()
    assert calls == []


@pytest.mark.asyncio
async def test_partial_initialization_cleans_only_created_queues():
    import json
    inventory = {"eth0": [], "ifb0": []}
    deletes = []
    class Runner:
        async def run(self, argv, **kwargs):
            if argv[:3] == ["tc", "-j", "qdisc"]:
                return CommandResult(0, json.dumps(inventory[argv[-1]]), "")
            if argv[:3] == ["tc", "qdisc", "add"]:
                dev = argv[argv.index("dev") + 1]
                inventory[dev].append({"handle": argv[argv.index("handle") + 1],
                    "kind": "ingress" if "ingress" in argv else "htb"})
            if argv[:3] == ["tc", "class", "add"]:
                raise CommandError("tc", CommandResult(4, "", "failed"))
            if argv[:3] == ["tc", "qdisc", "del"]:
                deletes.append(argv)
                dev = argv[argv.index("dev") + 1]
                inventory[dev] = [q for q in inventory[dev] if q["handle"] != argv[-1]]
            return CommandResult(0, "", "")
    controller = TrafficController("eth0", runner=Runner())
    with pytest.raises(CommandError):
        await controller.initialize()
    await controller.shutdown()
    assert len(deletes) == 1
    assert all("ifb0" not in call for call in deletes)
    assert inventory == {"eth0": [], "ifb0": []}


@pytest.mark.asyncio
async def test_changed_queue_kind_is_not_deleted():
    calls = []
    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            return CommandResult(0, '[{"kind":"fq_codel","handle":"1:","root":true}]', "")
    controller = TrafficController("eth0", runner=Runner())
    controller._owned_qdiscs.append(("eth0", "root", "1:", "htb"))
    with pytest.raises(ExceptionGroup):
        await controller.shutdown()
    assert all("del" not in call for call in calls)
    assert controller._owned_qdiscs


@pytest.mark.asyncio
async def test_restart_adopts_only_a_durably_owned_controller_layout(tmp_path):
    class Runner:
        async def run(self, argv, **kwargs):
            if argv[:4] == ["tc", "-j", "qdisc", "show"]:
                return CommandResult(0, '[{"kind":"htb","handle":"1:","root":true,"options":{"default":9999}}]', "")
            if argv[:4] == ["tc", "-j", "class", "show"]:
                return CommandResult(0, '[{"classid":"1:1"},{"classid":"1:9999"}]', "")
            return CommandResult(0, "", "")

    marker = tmp_path / "traffic-owner.json"
    marker.write_text('{"interface": "eth0", "handle": "1:", "kind": "htb"}')
    controller = TrafficController("eth0", runner=Runner(), ownership_file=marker)
    await controller.initialize()
    assert controller._initialized
    assert controller._owned_qdiscs == [("eth0", "root", "1:", "htb")]


@pytest.mark.asyncio
async def test_matching_foreign_htb_layout_is_not_adopted(tmp_path):
    class Runner:
        async def run(self, argv, **kwargs):
            if argv[:4] == ["tc", "-j", "qdisc", "show"]:
                return CommandResult(0, '[{"kind":"htb","handle":"1:","root":true,"options":{"default":9999}}]', "")
            if argv[:4] == ["tc", "-j", "class", "show"]:
                return CommandResult(0, '[{"classid":"1:1"},{"classid":"1:9999"}]', "")
            return CommandResult(0, "", "")

    with pytest.raises(RuntimeError, match="must be preserved"):
        await TrafficController("eth0", runner=Runner(), ownership_file=tmp_path / "missing").initialize()


@pytest.mark.asyncio
async def test_partial_limit_removal_retries_only_resources_still_present():
    calls = []
    class Runner:
        def __init__(self):
            self.failed = False

        async def run(self, argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ["tc", "class", "del"] and not self.failed:
                self.failed = True
                raise CommandError("tc", CommandResult(4, "", "temporary failure"))
            return CommandResult(0, "", "")

    controller = TrafficController("eth0", runner=Runner())
    mac = "AA:BB:CC:DD:EE:03"
    controller._limits[mac] = BandwidthLimit(mac, 1000, 500, 10)

    assert await controller.remove_bandwidth_limit(mac) is False
    first_filter = ["tc", "filter", "del", "dev", "eth0", "parent", "1:", "protocol", "ip", "pref", "10", "handle", "10", "flower"]
    assert calls.count(first_filter) == 1
    assert await controller.remove_bandwidth_limit(mac) is True
    assert calls.count(first_filter) == 1
