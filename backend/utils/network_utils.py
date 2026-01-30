"""Network utility functions."""

import re
import socket
import struct
import fcntl
import subprocess
import ipaddress
from typing import Optional, Tuple, List
import logging

logger = logging.getLogger(__name__)


def get_interface_ip(interface: str) -> Optional[str]:
    """Get the IP address of a network interface."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_bytes = fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24]
        return socket.inet_ntoa(ip_bytes)
    except (IOError, OSError) as e:
        logger.error(f"Failed to get IP for interface {interface}: {e}")
        return None


def get_interface_mac(interface: str) -> Optional[str]:
    """Get the MAC address of a network interface."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(
            sock.fileno(),
            0x8927,  # SIOCGIFHWADDR
            struct.pack('256s', interface[:15].encode('utf-8'))
        )
        mac_bytes = info[18:24]
        return ':'.join(f'{b:02X}' for b in mac_bytes)
    except (IOError, OSError) as e:
        logger.error(f"Failed to get MAC for interface {interface}: {e}")
        return None


def get_interface_netmask(interface: str) -> Optional[str]:
    """Get the netmask of a network interface."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        netmask_bytes = fcntl.ioctl(
            sock.fileno(),
            0x891b,  # SIOCGIFNETMASK
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24]
        return socket.inet_ntoa(netmask_bytes)
    except (IOError, OSError) as e:
        logger.error(f"Failed to get netmask for interface {interface}: {e}")
        return None


def get_default_gateway() -> Optional[Tuple[str, str]]:
    """
    Get the default gateway IP and interface.

    Returns:
        Tuple of (gateway_ip, interface) or None
    """
    try:
        # Read routing table
        with open('/proc/net/route', 'r') as f:
            for line in f.readlines()[1:]:  # Skip header
                fields = line.strip().split()
                if fields[1] == '00000000':  # Default route
                    interface = fields[0]
                    gateway_hex = fields[2]
                    # Convert hex to IP (little-endian)
                    gateway_ip = socket.inet_ntoa(
                        struct.pack('<I', int(gateway_hex, 16))
                    )
                    return gateway_ip, interface
    except Exception as e:
        logger.error(f"Failed to get default gateway: {e}")

    return None


def get_network_subnet(interface: str) -> Optional[str]:
    """
    Get the network subnet in CIDR notation for an interface.

    Returns:
        Subnet in CIDR notation (e.g., "192.168.1.0/24")
    """
    ip = get_interface_ip(interface)
    netmask = get_interface_netmask(interface)

    if not ip or not netmask:
        return None

    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except ValueError as e:
        logger.error(f"Failed to calculate subnet: {e}")
        return None


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private."""
    try:
        return ipaddress.IPv4Address(ip).is_private
    except ValueError:
        return False


def get_hostname_from_ip(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def enable_ip_forwarding() -> bool:
    """Enable IP forwarding in kernel."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        logger.info("IP forwarding enabled")
        return True
    except IOError as e:
        logger.error(f"Failed to enable IP forwarding: {e}")
        return False


def disable_ip_forwarding() -> bool:
    """Disable IP forwarding in kernel."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('0')
        logger.info("IP forwarding disabled")
        return True
    except IOError as e:
        logger.error(f"Failed to disable IP forwarding: {e}")
        return False


def get_ip_forwarding_status() -> bool:
    """Check if IP forwarding is enabled."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            return f.read().strip() == '1'
    except IOError:
        return False


def list_network_interfaces() -> List[str]:
    """List all network interfaces."""
    interfaces = []
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f.readlines()[2:]:  # Skip headers
                interface = line.split(':')[0].strip()
                if interface and interface != 'lo':
                    interfaces.append(interface)
    except IOError as e:
        logger.error(f"Failed to list interfaces: {e}")

    return interfaces


def run_command(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    """
    Run a system command safely.

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
