from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from threading import Event

import pytest

from core.inline_inspector import InlineInspector
from core.nfqueue_worker import NFQueueWorker
import core.nfqueue_worker as nfqueue_worker
from test_inline_inspector import IP as DEVICE_IP, MAC, Matcher, tls_client_hello


class QueuedPacket:
    def __init__(self, payload):
        self.payload = payload
        self.retained = False
        self.verdict = None

    def get_payload(self):
        return self.payload

    def retain(self):
        self.retained = True

    def accept(self):
        assert self.verdict is None
        self.verdict = "accept"

    def drop(self):
        assert self.verdict is None
        self.verdict = "drop"


def engine():
    value = InlineInspector(Matcher())
    value.set_device(DEVICE_IP, MAC)
    return value


def test_worker_retains_split_flow_then_drops_every_packet_before_logging_event():
    hello = tls_client_hello("blocked.example")
    split = len(hello) // 2
    first = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="198.51.100.10")
        / TCP(sport=50000, dport=443, seq=1000)
        / Raw(hello[:split])
    ))
    second = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="198.51.100.10")
        / TCP(sport=50000, dport=443, seq=1000 + split)
        / Raw(hello[split:])
    ))
    events = []

    def submit(event):
        assert first.verdict == second.verdict == "drop"
        events.append(event)
        return True

    worker = NFQueueWorker(engine(), submit)
    worker.handle_packet(first)
    assert first.retained and first.verdict is None
    worker.handle_packet(second)

    assert len(events) == 1
    event = events[0]
    assert (event.mac, event.domain, event.action, event.protocol, event.reason) == (
        MAC,
        "blocked.example",
        "blocked",
        "tls_sni",
        "blocked.example",
    )


def test_worker_accepts_allowed_dns_without_emitting_block_event():
    from scapy.layers.dns import DNS, DNSQR

    packet = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="192.0.2.53")
        / UDP(sport=50000, dport=53)
        / DNS(id=8, rd=1, qd=DNSQR(qname="allowed.example."))
    ))
    events = []
    worker = NFQueueWorker(engine(), events.append)

    worker.handle_packet(packet)

    assert packet.verdict == "accept"
    assert events == []


def test_malformed_queued_ip_payload_is_dropped():
    packet = QueuedPacket(b"not-an-ip-packet")
    NFQueueWorker(engine(), lambda event: True).handle_packet(packet)
    assert packet.verdict == "drop"


def test_worker_drops_and_logs_packets_when_inspection_deadline_expires():
    now = [1.0]
    inspected = InlineInspector(Matcher(), deadline_seconds=5, clock=lambda: now[0])
    inspected.set_device(DEVICE_IP, MAC)
    packet = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="198.51.100.10")
        / TCP(sport=50000, dport=443, seq=1000)
        / Raw(b"\x16\x03")
    ))
    events = []
    worker = NFQueueWorker(inspected, events.append)
    worker.handle_packet(packet)
    now[0] = 6.1

    worker.poll_timeouts()

    assert packet.verdict == "drop"
    assert len(events) == 1
    assert events[0].reason == "inspection_timeout"


def test_worker_decodes_tcp_teardown_flags_and_drops_undecided_flow():
    inspected = engine()
    first = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="198.51.100.10")
        / TCP(sport=50000, dport=443, seq=1000)
        / Raw(b"\x16\x03")
    ))
    reset = QueuedPacket(bytes(
        IP(src=DEVICE_IP, dst="198.51.100.10")
        / TCP(sport=50000, dport=443, seq=1002, flags="R")
    ))
    events = []
    worker = NFQueueWorker(inspected, events.append)

    worker.handle_packet(first)
    worker.handle_packet(reset)

    assert first.verdict == reset.verdict == "drop"
    assert events[0].reason == "connection_closed_before_inspection"


class Queue:
    def __init__(self):
        self.bound = None
        self.ran = Event()
        self.unbound = False

    def bind(self, *args, **kwargs):
        self.bound = (args, kwargs)

    def run(self, *, block):
        assert block is False
        self.ran.set()
        raise BlockingIOError

    def unbind(self):
        self.unbound = True


def test_worker_binds_with_bounded_queue_and_stops_cleanly():
    queue = Queue()
    worker = NFQueueWorker(engine(), lambda event: True, queue_factory=lambda: queue)

    worker.start()
    assert queue.ran.wait(1)
    assert worker.is_healthy
    worker.stop()

    assert queue.bound[0][0] == 100
    assert queue.bound[1] == {"max_len": 1024, "range": 65535}
    assert queue.unbound
    assert not worker.is_healthy


def test_worker_unbinds_when_thread_cannot_start(monkeypatch):
    queue = Queue()

    class FailedThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("thread unavailable")

    monkeypatch.setattr(nfqueue_worker, "Thread", FailedThread)
    worker = NFQueueWorker(engine(), lambda event: True, queue_factory=lambda: queue)

    with pytest.raises(RuntimeError, match="thread unavailable"):
        worker.start()

    assert queue.unbound
    assert not worker.is_healthy
    monkeypatch.undo()
    queue.unbound = False
    worker.start()
    worker.stop()
