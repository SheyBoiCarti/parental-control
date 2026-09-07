"""Privileged checks that run only inside the disposable CI network namespace."""

import json
import os
import subprocess

import pytest

from core.content_blocker import ContentBlocker
from core.content_enforcer import ContentEnforcer
from core.device_blocker import DeviceBlocker
from core.inline_inspector import InlineInspector
from core.nfqueue_worker import NFQueueWorker
from core.traffic_controller import TrafficController


pytestmark = pytest.mark.skipif(
    os.environ.get("PC_DISPOSABLE_NETNS") != "1",
    reason="requires the disposable Linux network namespace harness",
)

INTERFACE = "pcdummy0"


def command(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, text=True, capture_output=True)


@pytest.mark.asyncio
async def test_real_directional_classes_have_readable_owned_counters():
    controller = TrafficController(INTERFACE)
    try:
        await controller.initialize()
        assert await controller.set_bandwidth_limit(
            "02:00:00:00:00:10",
            2000,
            500,
            ip_address="192.0.2.10",
        )
        counters = await controller.read_bandwidth_counters()
        assert counters["02:00:00:00:00:10"]["bytes_sent"] == 0
        assert counters["02:00:00:00:00:10"]["bytes_received"] == 0

        classes = json.loads(command(
            "tc", "-j", "class", "show", "dev", INTERFACE,
        ).stdout)
        handles = {item.get("handle") or item.get("classid") for item in classes}
        assert {"1:a", "1:b"}.issubset(handles)
    finally:
        await controller.shutdown()

    inventory = json.loads(command(
        "tc", "-j", "qdisc", "show", "dev", INTERFACE,
    ).stdout)
    assert all(item.get("kind") != "htb" for item in inventory)


@pytest.mark.asyncio
async def test_real_block_chain_uses_owned_rules_and_cleans_up_exactly():
    blocker = DeviceBlocker(INTERFACE)
    try:
        await blocker.initialize()
        assert await blocker.block_device("02:00:00:00:00:11")
        rules = command("iptables-save", "-t", "filter").stdout
        assert "parental-control:block-hook" in rules
        assert "parental-control:block:020000000011" in rules
    finally:
        await blocker.shutdown()

    rules = command("iptables-save", "-t", "filter").stdout
    assert "PARENTAL_BLOCK" not in rules


@pytest.mark.asyncio
async def test_real_content_queue_binds_before_owned_firewall_hook():
    blocker = ContentBlocker()
    inspector = InlineInspector(blocker)
    worker = NFQueueWorker(inspector, lambda event: True, queue_number=110)
    enforcer = ContentEnforcer(INTERFACE, inspector, worker=worker)
    try:
        await enforcer.initialize()
        assert worker.is_healthy
        assert await enforcer.apply_device(
            "02:00:00:00:00:12",
            "192.0.2.12",
            [],
        )
        rules = command("iptables-save", "-t", "filter").stdout
        assert "parental-control:content-hook" in rules
        assert "parental-control:content:020000000012" in rules
        assert "--queue-num 110" in rules
    finally:
        await enforcer.shutdown()

    rules = command("iptables-save", "-t", "filter").stdout
    assert "PARENTAL_CONTENT" not in rules
