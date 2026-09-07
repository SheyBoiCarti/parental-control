"""Linux NFQUEUE worker that turns pure inspection decisions into verdicts."""

from __future__ import annotations

import logging
from threading import Event, Thread

from scapy.layers.inet import IP, TCP, UDP

from core.inline_inspector import PacketView
from core.packet_events import AccessEvent


logger = logging.getLogger(__name__)


class NFQueueWorker:
    def __init__(self, inspector, event_sink, *, queue_number=100, queue_factory=None):
        self._inspector = inspector
        self._event_sink = event_sink
        self.queue_number = queue_number
        self._queue_factory = queue_factory
        self._queue = None
        self._thread = None
        self._stop = Event()
        self._pending: dict[tuple, list] = {}
        self._failure: BaseException | None = None

    @staticmethod
    def _flow_key(view: PacketView) -> tuple:
        return (
            view.src_ip,
            view.dst_ip,
            view.src_port,
            view.dst_port,
            view.protocol,
        )

    @property
    def is_healthy(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and self._failure is None
        )

    @staticmethod
    def _decode(payload: bytes) -> PacketView:
        packet = IP(payload)
        if packet.version != 4:
            raise ValueError("queued packet is not IPv4")
        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "tcp"
            sequence = int(transport.seq)
            tcp_flags = int(transport.flags)
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "udp"
            sequence = None
            tcp_flags = 0
        else:
            raise ValueError("queued packet has unsupported transport")
        return PacketView(
            src_ip=packet.src,
            dst_ip=packet.dst,
            src_port=int(transport.sport),
            dst_port=int(transport.dport),
            protocol=protocol,
            payload=bytes(transport.payload),
            sequence=sequence,
            tcp_flags=tcp_flags,
        )

    def handle_packet(self, packet) -> None:
        """Issue exactly one verdict, retaining split flows until decided."""
        try:
            view = self._decode(packet.get_payload())
            verdict = self._inspector.inspect(view)
        except Exception:
            logger.exception("Malformed packet received from owned content queue")
            packet.drop()
            return

        key = self._flow_key(view)
        if verdict.action == "hold":
            packet.retain()
            self._pending.setdefault(key, []).append(packet)
            return

        queued = self._pending.pop(key, [])
        queued.append(packet)
        operation = "drop" if verdict.action == "drop" else "accept"
        for held in queued:
            getattr(held, operation)()

        if verdict.action == "drop":
            self._emit_drop(verdict, view.src_ip, view.dst_ip)

    def _emit_drop(self, verdict, src_ip: str, dst_ip: str) -> None:
        mac = self._inspector.get_device_mac(src_ip)
        if mac:
            self._event_sink(AccessEvent(
                mac=mac,
                domain=verdict.domain or dst_ip,
                action="blocked",
                app_name=verdict.app_name,
                rule_id=verdict.rule_id,
                protocol=verdict.protocol,
                reason=verdict.reason,
            ))

    def poll_timeouts(self) -> None:
        for key, verdict in self._inspector.expire():
            packets = self._pending.pop(key, [])
            for packet in packets:
                packet.drop()
            if packets:
                self._emit_drop(verdict, key[0], key[1])

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("NFQUEUE worker is already started")
        factory = self._queue_factory
        if factory is None:
            from netfilterqueue import NetfilterQueue
            factory = NetfilterQueue
        self._queue = factory()
        try:
            self._queue.bind(
                self.queue_number,
                self.handle_packet,
                max_len=1024,
                range=65535,
            )
            self._stop.clear()
            self._failure = None

            def run() -> None:
                try:
                    while not self._stop.is_set():
                        try:
                            self._queue.run(block=False)
                        except BlockingIOError:
                            pass
                        self.poll_timeouts()
                        self._stop.wait(0.01)
                except BaseException as error:
                    self._failure = error
                    logger.exception("NFQUEUE worker failed")

            self._thread = Thread(
                target=run,
                name="parental-content-nfqueue",
                daemon=False,
            )
            self._thread.start()
        except BaseException:
            try:
                self._queue.unbind()
            finally:
                self._queue = None
                self._thread = None
                self._stop.set()
            raise

    def stop(self, timeout=2.0) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise RuntimeError("NFQUEUE worker did not stop")
        for packets in self._pending.values():
            for packet in packets:
                packet.drop()
        self._pending.clear()
        self._queue.unbind()
        self._queue = None
        self._thread = None
        if self._failure is not None:
            failure = self._failure
            self._failure = None
            raise RuntimeError("NFQUEUE worker failed") from failure
