import pytest
from core.traffic_controller import TrafficController
from utils.commands import CommandResult


@pytest.mark.asyncio
async def test_upload_and_download_have_distinct_ip_classifiers_and_rates():
    calls = []
    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            return CommandResult(0, "[]", "")
    controller = TrafficController("eth0", runner=Runner())
    await controller.initialize()
    assert await controller.set_bandwidth_limit("AA:BB:CC:DD:EE:01", 2000, 500, ip_address="192.0.2.3")
    filters = [call for call in calls if call[1:3] == ["filter", "replace"]]
    assert len(filters) == 2
    upload = next(call for call in filters if "src_ip" in call)
    download = next(call for call in filters if "dst_ip" in call)
    assert upload[upload.index("src_ip") + 1] == "192.0.2.3/32"
    assert download[download.index("dst_ip") + 1] == "192.0.2.3/32"
    assert upload[-1] != download[-1]
    classes = {call[call.index("classid") + 1]: call for call in calls if call[1:3] == ["class", "replace"]}
    assert "500kbit" in classes[upload[-1]]
    assert "2000kbit" in classes[download[-1]]
    assert all(call[0] == "tc" and "ifb0" not in call and "MARK" not in call for call in calls)


@pytest.mark.asyncio
async def test_new_limit_rolls_back_every_created_resource_after_partial_failure():
    calls = []

    class Runner:
        async def run(self, argv, **kwargs):
            calls.append(argv)
            if argv[1:3] == ["filter", "replace"] and "dst_ip" in argv:
                raise RuntimeError("injected destination classifier failure")
            return CommandResult(0, "[]", "")

    controller = TrafficController("eth0", runner=Runner())
    await controller.initialize()

    assert not await controller.set_bandwidth_limit(
        "AA:BB:CC:DD:EE:01", 2000, 500, ip_address="192.0.2.3"
    )
    assert await controller.get_bandwidth_limit("AA:BB:CC:DD:EE:01") is None

    cleanup = [call for call in calls if call[1] in {"filter", "class"} and call[2] == "del"]
    assert [call[1] for call in cleanup] == ["class", "filter", "class"]
    assert cleanup[0][cleanup[0].index("classid") + 1] == "1:b"
    assert cleanup[1][cleanup[1].index("pref") + 1] == "10"
    assert cleanup[2][cleanup[2].index("classid") + 1] == "1:a"


@pytest.mark.asyncio
async def test_failed_limit_update_restores_previous_kernel_configuration():
    calls = []
    fail_next_download = False

    class Runner:
        async def run(self, argv, **kwargs):
            nonlocal fail_next_download
            calls.append(argv)
            if fail_next_download and argv[1:3] == ["filter", "replace"] and "dst_ip" in argv:
                fail_next_download = False
                raise RuntimeError("injected update failure")
            return CommandResult(0, "[]", "")

    controller = TrafficController("eth0", runner=Runner())
    assert await controller.set_bandwidth_limit(
        "AA:BB:CC:DD:EE:01", 2000, 500, ip_address="192.0.2.3"
    )
    calls.clear()
    fail_next_download = True

    assert not await controller.set_bandwidth_limit(
        "AA:BB:CC:DD:EE:01", 9000, 8000, ip_address="192.0.2.9"
    )
    retained = await controller.get_bandwidth_limit("AA:BB:CC:DD:EE:01")
    assert retained is not None
    assert (retained.download_kbps, retained.upload_kbps, retained.ip_address) == (
        2000,
        500,
        "192.0.2.3",
    )

    restored_filters = [call for call in calls if call[1:3] == ["filter", "replace"]][-2:]
    assert "192.0.2.3/32" in restored_filters[0]
    assert "192.0.2.3/32" in restored_filters[1]
    restored_classes = [call for call in calls if call[1:3] == ["class", "replace"]][-2:]
    assert "500kbit" in restored_classes[0]
    assert "2000kbit" in restored_classes[1]
