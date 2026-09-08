"""Pure bounded protocol inspection for packets held by an inline queue."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
import time

from scapy.layers.dns import DNS, DNSQR

from utils.domains import canonical_domain
from utils.mac_utils import normalize_mac


@dataclass(frozen=True)
class PacketView:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes
    sequence: int | None = None
    tcp_flags: int = 0


@dataclass(frozen=True)
class InspectionVerdict:
    action: str
    domain: str | None = None
    protocol: str | None = None
    reason: str | None = None
    rule_id: int | None = None
    app_name: str | None = None


@dataclass
class _Flow:
    created_at: float
    chunks: dict[int, bytes] = field(default_factory=dict)

    def add(self, sequence: int, payload: bytes) -> None:
        previous = self.chunks.get(sequence)
        if previous is None or len(payload) > len(previous):
            self.chunks[sequence] = payload

    def assembled(self) -> bytes:
        if not self.chunks:
            return b""
        positions = sorted(self.chunks)
        cursor = positions[0]
        output = bytearray()
        for position in positions:
            payload = self.chunks[position]
            if position > cursor:
                break
            overlap = max(0, cursor - position)
            if overlap < len(payload):
                output.extend(payload[overlap:])
                cursor = position + len(payload)
        return bytes(output)

    def size(self) -> int:
        return sum(len(value) for value in self.chunks.values())


class InlineInspector:
    """Return accept/drop/hold decisions without issuing kernel verdicts."""

    def __init__(
        self,
        matcher,
        *,
        inspection_budget: int = 64 * 1024,
        deadline_seconds: float = 5,
        max_flows: int = 1024,
        decision_ttl_seconds: float = 300,
        clock=time.monotonic,
    ):
        self._matcher = matcher
        self._budget = inspection_budget
        self._deadline = deadline_seconds
        self._max_flows = max_flows
        self._decision_ttl = decision_ttl_seconds
        self._clock = clock
        self._devices: dict[str, str] = {}
        self._flows: dict[tuple, _Flow] = {}
        self._allowed_flows: dict[tuple, float] = {}
        self._invalidated_flows: set[tuple] = set()

    def set_device(self, ip_address: str, mac: str) -> None:
        for key in [key for key in self._allowed_flows if key[0] == ip_address]:
            self._allowed_flows.pop(key, None)
            self._invalidated_flows.add(key)
        self._devices[ip_address] = normalize_mac(mac)

    def remove_device(self, ip_address: str) -> None:
        self._devices.pop(ip_address, None)
        for key in [key for key in self._flows if key[0] == ip_address]:
            self._flows.pop(key, None)
        self._allowed_flows = {
            key: created_at
            for key, created_at in self._allowed_flows.items()
            if key[0] != ip_address
        }
        self._invalidated_flows = {
            key for key in self._invalidated_flows if key[0] != ip_address
        }

    def get_device_mac(self, ip_address: str) -> str | None:
        return self._devices.get(ip_address)

    def expire(self) -> list[tuple[tuple, InspectionVerdict]]:
        """Remove overdue undecided flows and return restrictive decisions."""
        now = self._clock()
        expired = []
        for key, flow in list(self._flows.items()):
            if now - flow.created_at <= self._deadline:
                continue
            self._flows.pop(key, None)
            protocol = "dns_tcp" if key[3] == 53 else "tls_sni"
            expired.append((
                key,
                InspectionVerdict("drop", protocol=protocol, reason="inspection_timeout"),
            ))
        return expired

    def inspect(self, packet: PacketView) -> InspectionVerdict:
        mac = self._devices.get(packet.src_ip)
        if mac is None:
            return InspectionVerdict("accept")
        protocol = packet.protocol.lower()
        if protocol == "udp":
            if packet.dst_port == 443:
                return InspectionVerdict("drop", protocol="quic", reason="quic_fallback_required")
            if packet.dst_port != 53:
                return InspectionVerdict("accept")
            return self._dns_verdict(mac, packet.payload, "dns_udp")
        if protocol != "tcp" or packet.dst_port not in {53, 443}:
            return InspectionVerdict("accept")
        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            protocol,
        )
        if key in self._invalidated_flows:
            self._invalidated_flows.remove(key)
            return InspectionVerdict(
                "drop",
                protocol="dns_tcp" if packet.dst_port == 53 else "tls_sni",
                reason="policy_changed",
            )
        if packet.tcp_flags & 0x05:
            was_undecided = self._flows.pop(key, None) is not None
            self._allowed_flows.pop(key, None)
            if was_undecided:
                return InspectionVerdict(
                    "drop",
                    protocol="dns_tcp" if packet.dst_port == 53 else "tls_sni",
                    reason="connection_closed_before_inspection",
                )
            return InspectionVerdict("accept")
        # A fresh client SYN can reuse the same 4-tuple after the previous
        # connection ended.  Never inherit that connection's allow decision.
        if packet.tcp_flags & 0x02 and not packet.tcp_flags & 0x10:
            self._allowed_flows.pop(key, None)
            # A few capture paths mark every client segment as SYN while a
            # split ClientHello is being assembled; retain an in-progress
            # flow, but discard any completed predecessor.
            if key not in self._flows:
                self._flows.pop(key, None)
        if packet.dst_port == 443 and key in self._allowed_flows:
            self._allowed_flows[key] = self._clock()
            return InspectionVerdict("accept", protocol="tls_sni")
        if not packet.payload:
            if key in self._flows:
                return InspectionVerdict(
                    "hold",
                    protocol="dns_tcp" if packet.dst_port == 53 else "tls_sni",
                )
            return InspectionVerdict("accept")
        if packet.sequence is None:
            return InspectionVerdict(
                "drop",
                protocol="dns_tcp" if packet.dst_port == 53 else "tls_sni",
                reason="missing_tcp_sequence",
            )
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self._max_flows:
                return InspectionVerdict("drop", reason="inspection_queue_full")
            flow = self._flows[key] = _Flow(self._clock())
        if self._clock() - flow.created_at > self._deadline:
            self._flows.pop(key, None)
            return InspectionVerdict("drop", reason="inspection_timeout")
        flow.add(packet.sequence, packet.payload)
        if flow.size() > self._budget:
            self._flows.pop(key, None)
            return InspectionVerdict("drop", reason="inspection_budget_exceeded")
        data = flow.assembled()

        if packet.dst_port == 53:
            verdict = self._tcp_dns_verdict(mac, data)
            if verdict.action != "hold":
                self._flows.pop(key, None)
            return verdict

        status, domain = _parse_tls_sni(data)
        if status == "incomplete":
            return InspectionVerdict("hold", protocol="tls_sni")
        self._flows.pop(key, None)
        if status == "malformed":
            return InspectionVerdict("drop", protocol="tls_sni", reason="malformed_tls")
        if domain is None:
            if self._remember_allowed_flow(key):
                return InspectionVerdict("accept", protocol="tls_sni")
            return InspectionVerdict("drop", protocol="tls_sni", reason="inspection_queue_full")
        verdict = self._domain_verdict(mac, domain, "tls_sni")
        if verdict.action == "accept":
            if not self._remember_allowed_flow(key):
                return InspectionVerdict("drop", protocol="tls_sni", reason="inspection_queue_full")
        return verdict

    def _remember_allowed_flow(self, key: tuple) -> bool:
        if key not in self._allowed_flows and len(self._allowed_flows) >= self._max_flows:
            return False
        self._allowed_flows[key] = self._clock()
        return True

    def _dns_verdict(self, mac: str, payload: bytes, protocol: str) -> InspectionVerdict:
        try:
            message = DNS(payload)
            questions = list(message.qd or [])
            if message.qr != 0 or not questions or not isinstance(questions[0], DNSQR):
                raise ValueError("not a DNS query")
            raw_name = questions[0].qname
            if not isinstance(raw_name, bytes):
                raise ValueError("missing DNS name")
            domain = canonical_domain(raw_name.decode("ascii").rstrip("."))
        except Exception:
            return InspectionVerdict("drop", protocol=protocol, reason="malformed_dns")
        return self._domain_verdict(mac, domain, protocol)

    def _tcp_dns_verdict(self, mac: str, data: bytes) -> InspectionVerdict:
        """Evaluate every complete DNS-over-TCP frame before releasing bytes."""
        position = 0
        last = InspectionVerdict("hold", protocol="dns_tcp")
        while position < len(data):
            if len(data) - position < 2:
                return InspectionVerdict("hold", protocol="dns_tcp")
            length = struct.unpack("!H", data[position:position + 2])[0]
            if length < 12:
                return InspectionVerdict("drop", protocol="dns_tcp", reason="malformed_dns")
            end = position + 2 + length
            if end > len(data):
                return InspectionVerdict("hold", protocol="dns_tcp")
            last = self._dns_verdict(mac, data[position + 2:end], "dns_tcp")
            if last.action == "drop":
                return last
            position = end
        return last

    def _domain_verdict(self, mac: str, domain: str, protocol: str) -> InspectionVerdict:
        if hasattr(self._matcher, "match"):
            match = self._matcher.match(mac, domain)
            if match:
                return InspectionVerdict(
                    "drop", domain, protocol, match.reason, match.rule_id, match.app_name
                )
            return InspectionVerdict("accept", domain, protocol)
        reason = self._matcher.should_block(mac, domain)
        if reason:
            return InspectionVerdict("drop", domain, protocol, str(reason))
        return InspectionVerdict("accept", domain, protocol)


def _parse_tls_sni(data: bytes) -> tuple[str, str | None]:
    """Parse a ClientHello across one or more complete TLS handshake records."""
    position = 0
    handshake = bytearray()
    expected = None
    while True:
        if len(data) - position < 5:
            return "incomplete", None
        if data[position] != 0x16:
            # The first observed segment may be a continuation that arrived
            # before the record header. Wait for an earlier sequence number.
            return ("incomplete", None) if position == 0 else ("malformed", None)
        record_length = struct.unpack("!H", data[position + 3:position + 5])[0]
        end = position + 5 + record_length
        if end > len(data):
            return "incomplete", None
        handshake.extend(data[position + 5:end])
        position = end
        if len(handshake) >= 4:
            if handshake[0] != 0x01:
                return "malformed", None
            expected = 4 + int.from_bytes(handshake[1:4], "big")
            if expected > 64 * 1024:
                return "malformed", None
            if len(handshake) >= expected:
                break
        if position == len(data):
            return "incomplete", None
    try:
        hello = memoryview(handshake)[4:expected]
        cursor = 2 + 32
        session_length = hello[cursor]
        cursor += 1 + session_length
        cipher_length = struct.unpack("!H", hello[cursor:cursor + 2])[0]
        cursor += 2 + cipher_length
        compression_length = hello[cursor]
        cursor += 1 + compression_length
        extensions_length = struct.unpack("!H", hello[cursor:cursor + 2])[0]
        cursor += 2
        extensions_end = cursor + extensions_length
        if extensions_end > len(hello):
            raise ValueError
        while cursor + 4 <= extensions_end:
            extension_type, extension_length = struct.unpack(
                "!HH", hello[cursor:cursor + 4]
            )
            cursor += 4
            extension_end = cursor + extension_length
            if extension_end > extensions_end:
                raise ValueError
            if extension_type == 0:
                if extension_length < 5:
                    raise ValueError
                list_length = struct.unpack("!H", hello[cursor:cursor + 2])[0]
                if list_length + 2 != extension_length or hello[cursor + 2] != 0:
                    raise ValueError
                name_length = struct.unpack("!H", hello[cursor + 3:cursor + 5])[0]
                if name_length + 5 != extension_length:
                    raise ValueError
                domain = bytes(hello[cursor + 5:extension_end]).decode("ascii")
                return "complete", canonical_domain(domain)
            cursor = extension_end
        return "complete", None
    except (IndexError, UnicodeDecodeError, ValueError, struct.error):
        return "malformed", None
