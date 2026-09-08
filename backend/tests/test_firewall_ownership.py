import pytest
from types import SimpleNamespace

from core.content_enforcer import ContentEnforcer
from core.inline_inspector import InlineInspector
from utils.commands import CommandResult


class Matcher:
    def should_block(self, mac, domain):
        return None


class Worker:
    def __init__(self, calls):
        self.calls = calls
        self.queue_number = 100
        self.healthy = True

    @property
    def is_healthy(self):
        return self.healthy

    def start(self):
        self.calls.append(["worker", "start"])

    def stop(self):
        self.calls.append(["worker", "stop"])


class Runner:
    def __init__(self, calls, *, chain_exists=False, chain_rules=""):
        self.calls = calls
        self.chain_exists = chain_exists
        self.chain_rules = chain_rules

    async def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["iptables", "-S", "PARENTAL_CONTENT"]:
            return CommandResult(
                0 if self.chain_exists else 1,
                self.chain_rules if self.chain_exists else "",
                "",
            )
        if argv[:4] == ["iptables", "-C", "FORWARD", "-m"]:
            return CommandResult(1, "", "")
        return CommandResult(0, "", "")


@pytest.mark.asyncio
async def test_foreign_rule_in_named_chain_is_preserved_and_startup_refuses():
    calls = []
    enforcer = ContentEnforcer(
        "eth0",
        InlineInspector(Matcher()),
        runner=Runner(
            calls,
            chain_exists=True,
            chain_rules="-N PARENTAL_CONTENT\n-A PARENTAL_CONTENT -j ACCEPT\n",
        ),
        worker=Worker(calls),
    )

    with pytest.raises(RuntimeError, match="foreign rules"):
        await enforcer.initialize()

    assert ["iptables", "-F", "PARENTAL_CONTENT"] not in calls
    assert ["iptables", "-X", "PARENTAL_CONTENT"] not in calls


@pytest.mark.asyncio
async def test_worker_starts_before_owned_hook_and_device_rules_are_exact():
    calls = []
    inspector = InlineInspector(Matcher())
    enforcer = ContentEnforcer(
        "eth0", inspector, runner=Runner(calls), worker=Worker(calls)
    )

    await enforcer.initialize()
    assert await enforcer.apply_device(
        "AA:BB:CC:DD:EE:31", "192.0.2.31", []
    )

    assert calls.index(["worker", "start"]) < next(
        index for index, call in enumerate(calls) if call[:3] == ["iptables", "-I", "FORWARD"]
    )
    device_rules = [call for call in calls if call[:3] == ["iptables", "-A", "PARENTAL_CONTENT"]]
    assert len(device_rules) == 3
    assert all("192.0.2.31" in call for call in device_rules)
    assert any("443" in call and "DROP" in call for call in device_rules)
    assert sum("NFQUEUE" in call for call in device_rules) == 2
    assert inspector.get_device_mac("192.0.2.31") == "AA:BB:CC:DD:EE:31"

    await enforcer.shutdown()
    hook_delete = next(
        index for index, call in enumerate(calls) if call[:3] == ["iptables", "-D", "FORWARD"]
    )
    assert hook_delete < calls.index(["worker", "stop"])


@pytest.mark.asyncio
async def test_failed_queue_worker_prevents_content_state_being_applied():
    calls = []
    worker = Worker(calls)
    enforcer = ContentEnforcer(
        "eth0", InlineInspector(Matcher()), runner=Runner(calls), worker=worker
    )
    await enforcer.initialize()
    worker.healthy = False

    assert not await enforcer.apply_device(
        "AA:BB:CC:DD:EE:32", "192.0.2.32", []
    )
    assert not any(call[:3] == ["iptables", "-A", "PARENTAL_CONTENT"] for call in calls)


@pytest.mark.asyncio
async def test_restart_reclaims_only_stale_rules_with_owned_comments():
    calls = []
    stale = (
        "-N PARENTAL_CONTENT\n"
        "-A PARENTAL_CONTENT -s 192.0.2.33 -p udp --dport 53 "
        "-m comment --comment parental-control:content:aabbccddee33 "
        "-j NFQUEUE --queue-num 100\n"
    )
    enforcer = ContentEnforcer(
        "eth0",
        InlineInspector(Matcher()),
        runner=Runner(calls, chain_exists=True, chain_rules=stale),
        worker=Worker(calls),
    )

    await enforcer.initialize()
    await enforcer.shutdown()

    assert [
        "iptables", "-D", "PARENTAL_CONTENT", "-s", "192.0.2.33",
        "-p", "udp", "--dport", "53", "-m", "comment", "--comment",
        "parental-control:content:aabbccddee33", "-j", "NFQUEUE",
        "--queue-num", "100",
    ] in calls
    assert ["iptables", "-N", "PARENTAL_CONTENT"] not in calls
    assert ["iptables", "-X", "PARENTAL_CONTENT"] in calls


@pytest.mark.asyncio
async def test_bandwidth_only_rule_change_does_not_reinstall_content_rules():
    calls = []
    enforcer = ContentEnforcer(
        "eth0", InlineInspector(Matcher()), runner=Runner(calls), worker=Worker(calls)
    )
    await enforcer.initialize()
    content = SimpleNamespace(
        id=1,
        rule_type="block_domain",
        rule_value={"domain": "blocked.example"},
        is_active=True,
    )
    initial_bandwidth = SimpleNamespace(
        id=2,
        rule_type="bandwidth",
        rule_value={"download_kbps": 1000, "upload_kbps": 500},
        is_active=True,
    )
    changed_bandwidth = SimpleNamespace(
        id=2,
        rule_type="bandwidth",
        rule_value={"download_kbps": 2000, "upload_kbps": 500},
        is_active=True,
    )

    assert await enforcer.apply_device(
        "AA:BB:CC:DD:EE:34", "192.0.2.34", [content, initial_bandwidth]
    )
    assert await enforcer.apply_device(
        "AA:BB:CC:DD:EE:34", "192.0.2.34", [content, changed_bandwidth]
    )

    additions = [
        call for call in calls
        if call[:3] == ["iptables", "-A", "PARENTAL_CONTENT"]
    ]
    assert len(additions) == 3


@pytest.mark.asyncio
async def test_partial_content_removal_retries_only_rules_still_present():
    calls = []

    class FailOnceRunner(Runner):
        def __init__(self):
            super().__init__(calls)
            self.deletions = 0
            self.failed = False

        async def run(self, argv, **kwargs):
            if argv[:3] == ["iptables", "-D", "PARENTAL_CONTENT"]:
                self.deletions += 1
                if self.deletions == 2 and not self.failed:
                    self.failed = True
                    raise RuntimeError("temporary failure")
            return await super().run(argv, **kwargs)

    enforcer = ContentEnforcer(
        "eth0", InlineInspector(Matcher()), runner=FailOnceRunner(), worker=Worker(calls)
    )
    await enforcer.initialize()
    assert await enforcer.apply_device("AA:BB:CC:DD:EE:35", "192.0.2.35", [])

    assert not await enforcer.remove_device("AA:BB:CC:DD:EE:35")
    first_removed = [
        call for call in calls
        if call[:3] == ["iptables", "-D", "PARENTAL_CONTENT"]
    ][0]
    assert await enforcer.remove_device("AA:BB:CC:DD:EE:35")
    deletions = [call for call in calls if call[:3] == ["iptables", "-D", "PARENTAL_CONTENT"]]
    assert deletions.count(first_removed) == 1
