"""Utility modules."""

from .mac_utils import normalize_mac, is_valid_mac, lookup_vendor
from importlib import import_module


def __getattr__(name):
    if name in __all__:
        return getattr(import_module(".network_utils", __name__), name)
    raise AttributeError(name)

__all__ = [
    'normalize_mac',
    'is_valid_mac',
    'lookup_vendor',
    'get_interface_ip',
    'get_interface_mac',
    'get_default_gateway',
    'get_network_subnet',
    'enable_ip_forwarding',
    'disable_ip_forwarding',
]
