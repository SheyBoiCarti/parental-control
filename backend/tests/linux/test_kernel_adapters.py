"""Privileged checks that run only inside the disposable CI network namespace."""

import json
import os
import re
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

        classes_raw = command(
            "tc", "-j", "class", "show", "dev", INTERFACE,
        ).stdout
        try:
            classes = json.loads(classes_raw)
            handles = {item.get("handle") or item.get("classid") for item in classes}
        except (ValueError, json.JSONDecodeError):
            handles = set(re.findall(r"class\s+\w+\s+([0-9a-fA-F:]+)", classes_raw))
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


@pytest.mark.asyncio
async def test_real_directional_classes_measure_traffic():
    from scapy.all import Ether, IP, ICMP, sendp

    controller = TrafficController(INTERFACE)
    try:
        await controller.initialize()
        assert await controller.set_bandwidth_limit(
            "02:00:00:00:00:10",
            2000,
            500,
            ip_address="192.0.2.10",
        )

        # Transmit upload packet (source = 192.0.2.10)
        upload_pkt = Ether(
            src="02:00:00:00:00:10", dst="02:00:00:00:00:01"
        ) / IP(src="192.0.2.10", dst="192.0.2.1") / ICMP()
        sendp(upload_pkt, iface=INTERFACE, verbose=0)

        # Transmit download packet (destination = 192.0.2.10)
        download_pkt = Ether(
            src="02:00:00:00:00:01", dst="02:00:00:00:00:10"
        ) / IP(src="192.0.2.1", dst="192.0.2.10") / ICMP()
        sendp(download_pkt, iface=INTERFACE, verbose=0)

        # Transmit packet for an unaffected control device (192.0.2.99)
        control_pkt = Ether(
            src="02:00:00:00:00:99", dst="02:00:00:00:00:01"
        ) / IP(src="192.0.2.99", dst="192.0.2.1") / ICMP()
        sendp(control_pkt, iface=INTERFACE, verbose=0)

        counters = await controller.read_bandwidth_counters()
        dev_stats = counters["02:00:00:00:00:10"]
        assert dev_stats["bytes_sent"] > 0
        assert dev_stats["bytes_received"] > 0
        assert dev_stats["ip_address"] == "192.0.2.10"
    finally:
        await controller.shutdown()


@pytest.mark.asyncio
async def test_foreign_iptables_and_chains_preserved_across_lifecycle():
    # Insert foreign rule in FORWARD and create a foreign chain
    command("iptables", "-N", "TEST_FOREIGN_CHAIN")
    command("iptables", "-A", "TEST_FOREIGN_CHAIN", "-j", "ACCEPT")
    command(
        "iptables", "-I", "FORWARD", "1",
        "-m", "comment", "--comment", "foreign-test-marker", "-j", "ACCEPT",
    )
    try:
        blocker = DeviceBlocker(INTERFACE)
        await blocker.initialize()
        await blocker.block_device("02:00:00:00:00:22")
        await blocker.unblock_device("02:00:00:00:00:22")
        await blocker.shutdown()

        rules = command("iptables-save", "-t", "filter").stdout
        assert "foreign-test-marker" in rules
        assert "TEST_FOREIGN_CHAIN" in rules
    finally:
        command(
            "iptables", "-D", "FORWARD",
            "-m", "comment", "--comment", "foreign-test-marker", "-j", "ACCEPT",
        )
        command("iptables", "-F", "TEST_FOREIGN_CHAIN")
        command("iptables", "-X", "TEST_FOREIGN_CHAIN")


@pytest.mark.asyncio
async def test_incompatible_existing_qdisc_refuses_startup_and_preserves_foreign_queue():
    command("tc", "qdisc", "add", "dev", INTERFACE, "root", "handle", "1:", "prio")
    controller = TrafficController(INTERFACE)
    try:
        with pytest.raises(RuntimeError, match="must be preserved"):
            await controller.initialize()

        qdiscs = json.loads(command("tc", "-j", "qdisc", "show", "dev", INTERFACE).stdout)
        assert any(item.get("kind") == "prio" for item in qdiscs)
    finally:
        command("tc", "qdisc", "del", "dev", INTERFACE, "root")


@pytest.mark.asyncio
async def test_foreign_rules_in_owned_chains_refuse_startup():
    # Test PARENTAL_BLOCK foreign rule refusal
    command("iptables", "-N", "PARENTAL_BLOCK")
    command("iptables", "-A", "PARENTAL_BLOCK", "-j", "ACCEPT")
    blocker = DeviceBlocker(INTERFACE)
    try:
        with pytest.raises(RuntimeError, match="foreign rules; startup refused"):
            await blocker.initialize()
    finally:
        command("iptables", "-F", "PARENTAL_BLOCK")
        command("iptables", "-X", "PARENTAL_BLOCK")

    # Test PARENTAL_CONTENT foreign rule refusal
    command("iptables", "-N", "PARENTAL_CONTENT")
    command("iptables", "-A", "PARENTAL_CONTENT", "-j", "ACCEPT")
    blocker_content = ContentBlocker()
    inspector = InlineInspector(blocker_content)
    worker = NFQueueWorker(inspector, lambda event: True, queue_number=112)
    enforcer = ContentEnforcer(INTERFACE, inspector, worker=worker)
    try:
        with pytest.raises(RuntimeError, match="foreign rules; startup refused"):
            await enforcer.initialize()
    finally:
        command("iptables", "-F", "PARENTAL_CONTENT")
        command("iptables", "-X", "PARENTAL_CONTENT")


@pytest.mark.asyncio
async def test_device_blocker_restart_recovers_stale_owned_rules():
    command("iptables", "-N", "PARENTAL_BLOCK")
    command(
        "iptables", "-A", "PARENTAL_BLOCK",
        "-m", "mac", "--mac-source", "02:00:00:00:00:88",
        "-m", "comment", "--comment", "parental-control:block:020000000088",
        "-j", "DROP",
    )
    blocker = DeviceBlocker(INTERFACE)
    try:
        await blocker.initialize()
        # Stale owned rule should have been cleaned up during initialize
        rules = command("iptables-save", "-t", "filter").stdout
        assert "020000000088" not in rules
        assert "parental-control:block-hook" in rules
    finally:
        await blocker.shutdown()
    rules = command("iptables-save", "-t", "filter").stdout
    assert "PARENTAL_BLOCK" not in rules
