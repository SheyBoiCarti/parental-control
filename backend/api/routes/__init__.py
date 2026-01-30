"""API routes package."""

from .devices import router as devices_router
from .rules import router as rules_router
from .stats import router as stats_router
from .settings import router as settings_router

__all__ = [
    'devices_router',
    'rules_router',
    'stats_router',
    'settings_router',
]
