import struct

from scapy.layers.dns import DNS, DNSQR

from core.inline_inspector import InlineInspector, PacketView


MAC = "AA:BB:CC:DD:EE:21"
IP = "192.0.2.21"


class Matcher:
    def should_block(self, mac, domain):
        assert mac == MAC
        return "blocked.example" if domain.lower() == "blocked.example" else None


def tls_client_hello(host: str) -> bytes:
    encoded = host.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(encoded)) + encoded
    sni = struct.pack("!H", len(server_name)) + server_name
    extension = b"\x00\x00" + struct.pack("!H", len(sni)) + sni
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def inspector():
    value = InlineInspector(Matcher())
    value.set_device(IP, MAC)
    return value


def test_udp_dns_verdict_uses_canonical_domain_policy():
    payload = bytes(DNS(id=7, rd=1, qd=DNSQR(qname="BLOCKED.EXAMPLE.")))

    verdict = inspector().inspect(PacketView(
        src_ip=IP,
        dst_ip="192.0.2.53",
        src_port=50000,
        dst_port=53,
        protocol="udp",
        payload=payload,
    ))

    assert verdict.action == "drop"
    assert verdict.domain == "blocked.example"
    assert verdict.protocol == "dns_udp"
    assert verdict.reason == "blocked.example"


def test_allowed_udp_dns_is_accepted_and_unrelated_traffic_is_untouched():
    allowed = bytes(DNS(id=8, rd=1, qd=DNSQR(qname="allowed.example.")))
    engine = inspector()

    assert engine.inspect(PacketView(
        IP, "192.0.2.53", 50000, 53, "udp", allowed
    )).action == "accept"
    assert engine.inspect(PacketView(
        IP, "192.0.2.99", 50000, 1234, "udp", b"anything"
    )).action == "accept"


def test_restricted_udp_443_is_dropped_to_force_tcp_fallback():
    verdict = inspector().inspect(PacketView(
        IP, "198.51.100.10", 50000, 443, "udp", b"quic"
    ))

    assert (verdict.action, verdict.protocol, verdict.reason) == (
        "drop",
        "quic",
        "quic_fallback_required",
    )


def test_split_tls_client_hello_is_held_until_sni_can_be_decided():
    hello = tls_client_hello("blocked.example")
    engine = inspector()
    split = len(hello) // 2

    first = engine.inspect(PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", hello[:split], sequence=1000
    ))
    second = engine.inspect(PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", hello[split:], sequence=1000 + split
    ))

    assert first.action == "hold"
    assert second.action == "drop"
    assert second.domain == "blocked.example"
    assert second.protocol == "tls_sni"


def test_malformed_dns_for_restricted_device_fails_closed():
    verdict = inspector().inspect(PacketView(
        IP, "192.0.2.53", 50000, 53, "udp", b"not-dns"
    ))

    assert (verdict.action, verdict.reason) == ("drop", "malformed_dns")


def test_out_of_order_and_retransmitted_tls_segments_wait_for_contiguous_hello():
    hello = tls_client_hello("blocked.example")
    engine = inspector()
    split = len(hello) // 2
    later = PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", hello[split:], sequence=2000 + split
    )
    earlier = PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", hello[:split], sequence=2000
    )

    assert engine.inspect(later).action == "hold"
    assert engine.inspect(later).action == "hold"
    verdict = engine.inspect(earlier)

    assert verdict.action == "drop"
    assert verdict.domain == "blocked.example"


def test_undecided_flow_expires_with_a_fail_closed_verdict():
    now = [10.0]
    engine = InlineInspector(Matcher(), deadline_seconds=5, clock=lambda: now[0])
    engine.set_device(IP, MAC)
    partial = PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", b"\x16\x03", sequence=1000
    )
    assert engine.inspect(partial).action == "hold"

    now[0] = 15.1
    expired = engine.expire()

    assert len(expired) == 1
    _, verdict = expired[0]
    assert (verdict.action, verdict.protocol, verdict.reason) == (
        "drop",
        "tls_sni",
        "inspection_timeout",
    )


def test_allowed_tls_flow_is_cached_and_rule_refresh_invalidates_it():
    engine = inspector()
    hello = tls_client_hello("allowed.example")
    first = PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", hello, sequence=1000
    )
    application_data = PacketView(
        IP,
        "198.51.100.10",
        50000,
        443,
        "tcp",
        b"\x17\x03\x03\x00\x01x",
        sequence=1000 + len(hello),
    )

    assert engine.inspect(first).action == "accept"
    assert engine.inspect(application_data).action == "accept"

    engine.set_device(IP, MAC)
    invalidated = engine.inspect(application_data)
    assert (invalidated.action, invalidated.reason) == ("drop", "policy_changed")


def test_allowed_tls_flow_stays_accepted_until_connection_teardown():
    now = [0.0]
    engine = InlineInspector(
        Matcher(), clock=lambda: now[0], decision_ttl_seconds=300
    )
    engine.set_device(IP, MAC)
    hello = tls_client_hello("allowed.example")
    first = PacketView(IP, "198.51.100.10", 50000, 443, "tcp", hello, sequence=1000)
    application_data = PacketView(
        IP, "198.51.100.10", 50000, 443, "tcp", b"encrypted", sequence=2000
    )
    assert engine.inspect(first).action == "accept"
    now[0] = 299
    assert engine.inspect(application_data).action == "accept"
    now[0] = 301
    assert engine.inspect(application_data).action == "accept"


def test_allowed_tls_decisions_have_a_hard_capacity_limit():
    engine = InlineInspector(Matcher(), max_flows=1)
    engine.set_device(IP, MAC)
    first = PacketView(IP, "198.51.100.10", 50000, 443, "tcp", tls_client_hello("allowed.example"), sequence=1000)
    second = PacketView(IP, "198.51.100.11", 50001, 443, "tcp", tls_client_hello("allowed.example"), sequence=2000)

    assert engine.inspect(first).action == "accept"
    verdict = engine.inspect(second)
    assert (verdict.action, verdict.reason) == ("drop", "inspection_queue_full")


def test_tcp_dns_packet_with_any_blocked_frame_is_dropped():
    allowed = bytes(DNS(id=8, rd=1, qd=DNSQR(qname="allowed.example.")))
    blocked = bytes(DNS(id=9, rd=1, qd=DNSQR(qname="blocked.example.")))
    payload = (
        struct.pack("!H", len(allowed)) + allowed
        + struct.pack("!H", len(blocked)) + blocked
    )

    verdict = inspector().inspect(PacketView(
        IP, "192.0.2.53", 50000, 53, "tcp", payload, sequence=1000
    ))

    assert (verdict.action, verdict.domain) == ("drop", "blocked.example")


def test_tcp_teardown_clears_cached_allow_decision():
    engine = inspector()
    hello = tls_client_hello("allowed.example")
    flow = dict(
        src_ip=IP,
        dst_ip="198.51.100.10",
        src_port=50000,
        dst_port=443,
        protocol="tcp",
    )

    assert engine.inspect(PacketView(**flow, payload=hello, sequence=1000)).action == "accept"
    assert engine.inspect(
        PacketView(**flow, payload=b"", sequence=1000 + len(hello), tcp_flags=0x01)
    ).action == "accept"

    assert engine.inspect(
        PacketView(**flow, payload=b"encrypted", sequence=2000)
    ).action == "hold"


def test_tcp_teardown_fails_closed_when_inspection_is_undecided():
    engine = inspector()
    flow = dict(
        src_ip=IP,
        dst_ip="198.51.100.10",
        src_port=50000,
        dst_port=443,
        protocol="tcp",
    )
    assert engine.inspect(
        PacketView(**flow, payload=b"\x16\x03", sequence=1000)
    ).action == "hold"

    verdict = engine.inspect(
        PacketView(**flow, payload=b"", sequence=1002, tcp_flags=0x04)
    )

    assert (verdict.action, verdict.reason) == (
        "drop",
        "connection_closed_before_inspection",
    )
