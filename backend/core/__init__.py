"""Core network control modules."""

from importlib import import_module

_EXPORTS = {
    "DeviceManager": "device_manager", "ARPSpoofer": "arp_spoofer",
    "PacketAnalyzer": "packet_analyzer", "TrafficController": "traffic_controller",
    "BandwidthMonitor": "traffic_controller", "ContentBlocker": "content_blocker",
    "DeviceBlocker": "device_blocker",
}


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(f".{_EXPORTS[name]}", __name__), name)

__all__ = [
    'DeviceManager',
    'ARPSpoofer',
    'PacketAnalyzer',
    'TrafficController',
    'BandwidthMonitor',
    'ContentBlocker',
    'DeviceBlocker',
]
