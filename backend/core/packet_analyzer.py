"""Packet analyzer for DNS and TLS SNI inspection."""

import asyncio
import logging
import struct
from typing import Optional, Dict, Callable, List, Set
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime

from scapy.all import (
    sniff, DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, conf
)

logger = logging.getLogger(__name__)
conf.verb = 0


@dataclass
class DNSQuery:
    """Represents a DNS query."""
    src_ip: str
    src_mac: str
    domain: str
    query_type: str
    timestamp: datetime


@dataclass
class TLSConnection:
    """Represents a TLS connection with SNI."""
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_port: int
    sni: str
    timestamp: datetime


class PacketAnalyzer:
    """
    Analyzes network packets for DNS queries and TLS SNI.

    Used to identify which domains/apps devices are accessing
    without decrypting traffic.
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._running = False
        self._sniff_task: Optional[asyncio.Task] = None

        # Callbacks
        self._dns_callbacks: List[Callable[[DNSQuery], None]] = []
        self._tls_callbacks: List[Callable[[TLSConnection], None]] = []

        # IP to MAC mapping (updated externally)
        self._ip_to_mac: Dict[str, str] = {}

        # Statistics
        self.dns_query_count = 0
        self.tls_connection_count = 0

    def set_ip_mac_mapping(self, mapping: Dict[str, str]):
        """Update IP to MAC address mapping."""
        self._ip_to_mac = mapping

    def add_dns_callback(self, callback: Callable[[DNSQuery], None]):
        """Add callback for DNS queries."""
        self._dns_callbacks.append(callback)

    def add_tls_callback(self, callback: Callable[[TLSConnection], None]):
        """Add callback for TLS connections."""
        self._tls_callbacks.append(callback)

    def _get_mac_for_ip(self, ip: str) -> str:
        """Get MAC address for IP."""
        return self._ip_to_mac.get(ip, "00:00:00:00:00:00")

    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            # Check for DNS
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self._process_dns(packet)

            # Check for TLS Client Hello (SNI extraction)
            elif packet.haslayer(TCP) and packet.haslayer(Raw):
                self._process_tls(packet)

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    def _process_dns(self, packet):
        """Process DNS packet."""
        try:
            dns = packet[DNS]
            if dns.qr == 0:  # Query (not response)
                query_name = dns.qd.qname.decode('utf-8').rstrip('.')
                query_type = self._dns_type_to_str(dns.qd.qtype)

                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                src_mac = self._get_mac_for_ip(src_ip)

                dns_query = DNSQuery(
                    src_ip=src_ip,
                    src_mac=src_mac,
                    domain=query_name,
                    query_type=query_type,
                    timestamp=datetime.utcnow()
                )

                self.dns_query_count += 1

                # Notify callbacks
                for callback in self._dns_callbacks:
                    try:
                        callback(dns_query)
                    except Exception as e:
                        logger.error(f"DNS callback error: {e}")

        except Exception as e:
            logger.debug(f"DNS processing error: {e}")

    def _dns_type_to_str(self, qtype: int) -> str:
        """Convert DNS query type to string."""
        types = {
            1: "A",
            28: "AAAA",
            5: "CNAME",
            15: "MX",
            16: "TXT",
            2: "NS",
            6: "SOA",
            12: "PTR",
            33: "SRV",
        }
        return types.get(qtype, str(qtype))

    def _process_tls(self, packet):
        """Process potential TLS Client Hello for SNI extraction."""
        try:
            raw_data = bytes(packet[Raw].load)

            # TLS record header: content_type (1) + version (2) + length (2)
            if len(raw_data) < 5:
                return

            content_type = raw_data[0]

            # 0x16 = Handshake
            if content_type != 0x16:
                return

            # Check for Client Hello (handshake type 0x01)
            if len(raw_data) < 6 or raw_data[5] != 0x01:
                return

            sni = self._extract_sni(raw_data)

            if sni:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                src_mac = self._get_mac_for_ip(src_ip)

                tls_conn = TLSConnection(
                    src_ip=src_ip,
                    src_mac=src_mac,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    sni=sni,
                    timestamp=datetime.utcnow()
                )

                self.tls_connection_count += 1

                # Notify callbacks
                for callback in self._tls_callbacks:
                    try:
                        callback(tls_conn)
                    except Exception as e:
                        logger.error(f"TLS callback error: {e}")

        except Exception as e:
            logger.debug(f"TLS processing error: {e}")

    def _extract_sni(self, data: bytes) -> Optional[str]:
        """
        Extract SNI from TLS Client Hello.

        The SNI is in the extensions section of the Client Hello.
        """
        try:
            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            pos = 5 + 4

            if len(data) < pos + 2:
                return None

            # Skip client version (2 bytes)
            pos += 2

            # Skip random (32 bytes)
            pos += 32

            if len(data) < pos + 1:
                return None

            # Skip session ID
            session_id_len = data[pos]
            pos += 1 + session_id_len

            if len(data) < pos + 2:
                return None

            # Skip cipher suites
            cipher_suites_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2 + cipher_suites_len

            if len(data) < pos + 1:
                return None

            # Skip compression methods
            compression_len = data[pos]
            pos += 1 + compression_len

            if len(data) < pos + 2:
                return None

            # Extensions length
            extensions_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2

            # Parse extensions to find SNI (type 0x0000)
            end = pos + extensions_len

            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = struct.unpack('!H', data[pos:pos+2])[0]
                ext_len = struct.unpack('!H', data[pos+2:pos+4])[0]
                pos += 4

                if ext_type == 0x0000:  # SNI extension
                    # SNI extension format:
                    # - list length (2 bytes)
                    # - name type (1 byte)
                    # - name length (2 bytes)
                    # - name (variable)

                    if pos + 5 > len(data):
                        return None

                    # Skip list length
                    name_type = data[pos + 2]
                    name_len = struct.unpack('!H', data[pos+3:pos+5])[0]

                    if name_type == 0:  # Host name
                        sni_start = pos + 5
                        sni_end = sni_start + name_len

                        if sni_end <= len(data):
                            return data[sni_start:sni_end].decode('utf-8')

                    return None

                pos += ext_len

        except Exception as e:
            logger.debug(f"SNI extraction error: {e}")

        return None

    async def start(self):
        """Start packet capture."""
        if self._running:
            return
        if self._sniff_task is not None:
            raise RuntimeError("Previous capture must be stopped before restarting")

        self._running = True

        def capture():
            """Wake periodically even when the interface receives no packets."""
            try:
                while self._running:
                    sniff(
                        iface=self.interface,
                        prn=self._process_packet,
                        filter="port 53 or port 443",
                        store=0,
                        timeout=0.5,
                        stop_filter=lambda _: not self._running,
                    )
            finally:
                self._running = False

        loop = asyncio.get_running_loop()
        self._sniff_task = loop.run_in_executor(None, capture)
        # Retrieve failures immediately, while preserving the exception for stop.
        def completed(task):
            if not task.cancelled() and task.exception() is not None:
                logger.error("Packet capture failed: %s", task.exception())
        self._sniff_task.add_done_callback(completed)

        logger.info(f"Packet analyzer started on {self.interface}")

    async def stop(self):
        """Stop packet capture."""
        self._running = False

        if self._sniff_task is not None:
            task = self._sniff_task
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2)
            finally:
                if task.done():
                    self._sniff_task = None

        logger.info("Packet analyzer stopped")

    def get_stats(self) -> Dict:
        """Get capture statistics."""
        return {
            "dns_queries": self.dns_query_count,
            "tls_connections": self.tls_connection_count,
            "running": self._running
        }
