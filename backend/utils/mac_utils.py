"""MAC address utilities including vendor lookup."""

import re
import json
from pathlib import Path
from typing import Optional

# OUI (Organizationally Unique Identifier) database
# This is a small subset - in production, use a full OUI database
OUI_DATABASE = {
    "00:00:0C": "Cisco",
    "00:00:5E": "IANA",
    "00:01:42": "Cisco",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "00:17:88": "Philips Hue",
    "00:1E:06": "Xiaomi",
    "04:CF:8C": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "98:FA:E3": "Xiaomi",
    "00:E0:4C": "Realtek",
    "52:54:00": "QEMU/KVM",
    "00:1A:79": "Dell",
    "00:21:9B": "Dell",
    "18:03:73": "Dell",
    "00:0C:76": "Micro-Star (MSI)",
    "00:21:70": "Dell",
    "24:B6:FD": "Dell",
    "00:30:48": "Supermicro",
    "AC:1F:6B": "Super Micro",
    "7C:C2:55": "Super Micro",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1E:C9": "Dell",
    "14:FE:B5": "Dell",
    "18:66:DA": "Dell",
    "00:25:64": "Dell",
    "00:1D:09": "Dell",
    "34:17:EB": "Dell",
    "98:90:96": "Dell",
    "00:26:B9": "Dell",
    "00:0D:56": "Dell",
    "00:12:3F": "Dell",
    "00:13:72": "Dell",
    "00:14:22": "Dell",
    "00:15:C5": "Dell",
    "00:18:8B": "Dell",
    "00:19:B9": "Dell",
    "00:1A:A0": "Dell",
    "00:1C:23": "Dell",
    "00:1D:09": "Dell",
    "00:1E:4F": "Dell",
    "00:1E:C9": "Dell",
    "00:21:70": "Dell",
    "00:21:9B": "Dell",
    "00:22:19": "Dell",
    "00:24:E8": "Dell",
    "A4:BA:DB": "Dell",
    "B8:AC:6F": "Dell",
    "F8:B1:56": "Dell",
    "B0:83:FE": "Dell",
    "74:86:7A": "Dell",
    "00:24:D7": "Intel",
    "00:1B:21": "Intel",
    "00:1C:C0": "Intel",
    "00:1D:E0": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:20:E0": "Intel",
    "00:21:5C": "Intel",
    "00:21:5D": "Intel",
    "00:21:6A": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:23:14": "Intel",
    "00:23:15": "Intel",
    "00:24:D6": "Intel",
    "00:26:C6": "Intel",
    "00:26:C7": "Intel",
    "3C:97:0E": "Intel",
    "40:25:C2": "Intel",
    "58:94:6B": "Intel",
    "5C:51:4F": "Intel",
    "64:80:99": "Intel",
    "6C:29:95": "Intel",
    "78:92:9C": "Intel",
    "80:86:F2": "Intel",
    "84:3A:4B": "Intel",
    "88:53:2E": "Intel",
    "8C:70:5A": "Intel",
    "94:65:9C": "Intel",
    "A0:36:9F": "Intel",
    "A4:34:D9": "Intel",
    "B4:6B:FC": "Intel",
    "B8:08:CF": "Intel",
    "BC:77:37": "Intel",
    "C8:1F:66": "Intel",
    "CC:3D:82": "Intel",
    "D0:50:99": "Intel",
    "D4:BE:D9": "Intel",
    "DC:53:60": "Intel",
    "E8:B1:FC": "Intel",
    "EC:55:F9": "Intel",
    "F4:8C:50": "Intel",
    "3C:D9:2B": "HP",
    "00:1E:0B": "HP",
    "00:21:5A": "HP",
    "00:25:B3": "HP",
    "2C:27:D7": "HP",
    "30:E1:71": "HP",
    "38:63:BB": "HP",
    "3C:4A:92": "HP",
    "48:0F:CF": "HP",
    "50:65:F3": "HP",
    "68:B5:99": "HP",
    "6C:3B:E5": "HP",
    "78:AC:C0": "HP",
    "80:CE:62": "HP",
    "8C:DC:D4": "HP",
    "94:57:A5": "HP",
    "98:4B:E1": "HP",
    "A0:2B:B8": "HP",
    "A0:D3:C1": "HP",
    "AC:16:2D": "HP",
    "B0:5A:DA": "HP",
    "B4:B5:2F": "HP",
    "C8:CB:B8": "HP",
    "D4:85:64": "HP",
    "D8:9D:67": "HP",
    "E4:11:5B": "HP",
    "E8:39:35": "HP",
    "EC:B1:D7": "HP",
    "F0:92:1C": "HP",
    "F4:CE:46": "HP",
    "00:1F:C6": "Samsung",
    "00:21:19": "Samsung",
    "00:23:39": "Samsung",
    "00:24:54": "Samsung",
    "00:26:37": "Samsung",
    "14:89:FD": "Samsung",
    "18:3F:47": "Samsung",
    "1C:62:B8": "Samsung",
    "20:64:32": "Samsung",
    "24:4B:81": "Samsung",
    "28:98:7B": "Samsung",
    "2C:AE:2B": "Samsung",
    "30:96:FB": "Samsung",
    "34:23:87": "Samsung",
    "38:01:97": "Samsung",
    "40:0E:85": "Samsung",
    "44:F4:59": "Samsung",
    "50:01:BB": "Samsung",
    "50:B7:C3": "Samsung",
    "54:88:0E": "Samsung",
    "5C:0A:5B": "Samsung",
    "60:A1:0A": "Samsung",
    "64:77:91": "Samsung",
    "68:EB:AE": "Samsung",
    "70:F9:27": "Samsung",
    "78:47:1D": "Samsung",
    "7C:0B:C6": "Samsung",
    "80:65:6D": "Samsung",
    "84:11:9E": "Samsung",
    "84:38:38": "Samsung",
    "88:32:9B": "Samsung",
    "8C:71:F8": "Samsung",
    "90:18:7C": "Samsung",
    "94:01:C2": "Samsung",
    "94:35:0A": "Samsung",
    "94:63:D1": "Samsung",
    "98:0C:82": "Samsung",
    "9C:02:98": "Samsung",
    "9C:3A:AF": "Samsung",
    "A0:07:98": "Samsung",
    "A0:82:1F": "Samsung",
    "A4:07:B6": "Samsung",
    "A8:06:00": "Samsung",
    "AC:36:13": "Samsung",
    "B0:47:BF": "Samsung",
    "B0:EC:71": "Samsung",
    "B4:3A:28": "Samsung",
    "B4:79:A7": "Samsung",
    "BC:14:EF": "Samsung",
    "BC:20:A4": "Samsung",
    "BC:44:86": "Samsung",
    "BC:72:B1": "Samsung",
    "C0:97:27": "Samsung",
    "C4:42:02": "Samsung",
    "C8:BA:94": "Samsung",
    "CC:07:AB": "Samsung",
    "D0:22:BE": "Samsung",
    "D0:59:E4": "Samsung",
    "D4:88:90": "Samsung",
    "D8:90:E8": "Samsung",
    "DC:71:44": "Samsung",
    "E4:12:1D": "Samsung",
    "E4:7C:F9": "Samsung",
    "E8:50:8B": "Samsung",
    "EC:1F:72": "Samsung",
    "EC:9B:F3": "Samsung",
    "F0:08:F1": "Samsung",
    "F0:25:B7": "Samsung",
    "F4:09:D8": "Samsung",
    "F4:42:8F": "Samsung",
    "F8:04:2E": "Samsung",
    "F8:77:B8": "Samsung",
    "FC:A1:3E": "Samsung",
    "FC:F1:36": "Samsung",
    "D4:38:9C": "Sony",
    "FC:F1:52": "Sony",
    "00:1A:80": "Sony",
    "00:1D:BA": "Sony",
    "00:13:A9": "Sony",
    "04:5D:4B": "Sony",
    "28:0D:FC": "Sony",
    "30:39:26": "Sony",
    "70:9E:29": "Sony",
    "78:84:3C": "Sony",
    "B4:52:7D": "Sony",
    "FC:0F:E6": "Sony",
}


def normalize_mac(mac: str) -> str:
    """
    Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX uppercase).

    Args:
        mac: MAC address in any common format

    Returns:
        Normalized MAC address

    Raises:
        ValueError: If MAC address is invalid
    """
    # Remove all separators and convert to uppercase
    mac_clean = re.sub(r'[:\-\.\s]', '', mac.upper())

    # Validate length
    if len(mac_clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")

    # Validate hex characters
    if not re.match(r'^[0-9A-F]{12}$', mac_clean):
        raise ValueError(f"Invalid MAC address: {mac}")

    # Format as XX:XX:XX:XX:XX:XX
    return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))


def is_valid_mac(mac: str) -> bool:
    """Check if a MAC address is valid."""
    try:
        normalize_mac(mac)
        return True
    except ValueError:
        return False


def get_oui(mac: str) -> str:
    """Get the OUI (first 3 bytes) of a MAC address."""
    normalized = normalize_mac(mac)
    return normalized[:8]


def lookup_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor/manufacturer from a MAC address.

    Args:
        mac: MAC address

    Returns:
        Vendor name or None if not found
    """
    try:
        oui = get_oui(mac)
        return OUI_DATABASE.get(oui)
    except ValueError:
        return None


def is_local_mac(mac: str) -> bool:
    """
    Check if MAC address is locally administered (vs universally administered).

    Locally administered addresses have the second-least-significant bit
    of the first octet set to 1.
    """
    try:
        normalized = normalize_mac(mac)
        first_byte = int(normalized[:2], 16)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def is_multicast_mac(mac: str) -> bool:
    """
    Check if MAC address is multicast.

    Multicast addresses have the least-significant bit of the first octet set to 1.
    """
    try:
        normalized = normalize_mac(mac)
        first_byte = int(normalized[:2], 16)
        return bool(first_byte & 0x01)
    except ValueError:
        return False


def is_broadcast_mac(mac: str) -> bool:
    """Check if MAC address is broadcast (FF:FF:FF:FF:FF:FF)."""
    try:
        normalized = normalize_mac(mac)
        return normalized == "FF:FF:FF:FF:FF:FF"
    except ValueError:
        return False
