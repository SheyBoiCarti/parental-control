"""Content blocker for app and domain blocking."""

import asyncio
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from sqlalchemy import select

from db.database import get_session
from db.models import AppSignature, DeviceRule
from utils.mac_utils import normalize_mac
from utils.domains import canonical_domain

logger = logging.getLogger(__name__)


@dataclass
class BlockRule:
    """A blocking rule for a device."""
    rule_type: str  # 'app' or 'domain'
    value: str      # app name or domain pattern
    domains: Set[str] = field(default_factory=set)  # Resolved domains for app
    rule_id: int | None = None


@dataclass(frozen=True)
class PolicyMatch:
    rule_id: int | None
    reason: str
    value: str
    app_name: str | None = None


class ContentBlocker:
    """
    Manages content blocking based on domain patterns.

    Resolves app/domain policy for DNS names and TLS SNI. This class returns
    a policy decision; the inline packet worker must enforce the verdict.
    """

    def __init__(self):
        self._device_rules: Dict[str, List[BlockRule]] = {}  # MAC -> rules
        self._app_signatures: Dict[str, List[str]] = {}  # app_name -> domain patterns
        self._initialized = False

    async def initialize(self):
        """Load app signatures from database."""
        if self._initialized:
            return

        await self._load_app_signatures()
        await self._load_device_rules()
        self._initialized = True
        logger.info("Content blocker initialized")

    async def _load_app_signatures(self):
        """Load app signatures from database."""
        async with get_session() as session:
            result = await session.execute(select(AppSignature))
            signatures = result.scalars().all()

            refreshed = {
                sig.app_name: [canonical_domain(domain) for domain in sig.domains]
                for sig in signatures
            }

        self._app_signatures = refreshed
        for rules in self._device_rules.values():
            for rule in rules:
                if rule.rule_type == 'app':
                    rule.domains = set(refreshed.get(rule.value, []))

        logger.info(f"Loaded {len(self._app_signatures)} app signatures")

    async def _load_device_rules(self):
        """Load device rules from database."""
        refreshed = {}
        async with get_session() as session:
            result = await session.execute(
                select(DeviceRule).where(
                    DeviceRule.rule_type.in_(['block_app', 'block_domain']),
                    DeviceRule.is_active == True
                )
            )
            rules = result.scalars().all()

            # Get device MACs
            from db.models import Device
            device_result = await session.execute(select(Device))
            devices = {d.id: d.mac_address for d in device_result.scalars().all()}

            for rule in rules:
                if rule.validation_error:
                    continue
                mac = devices.get(rule.device_id)
                if not mac:
                    continue

                if mac not in refreshed:
                    refreshed[mac] = []

                if rule.rule_type == 'block_app':
                    app_name = rule.rule_value.get('app')
                    if app_name and app_name in self._app_signatures:
                        block_rule = BlockRule(
                            rule_type='app',
                            value=app_name,
                            domains=set(self._app_signatures[app_name]),
                            rule_id=rule.id,
                        )
                        refreshed[mac].append(block_rule)

                elif rule.rule_type == 'block_domain':
                    domain = rule.rule_value.get('domain')
                    if domain:
                        block_rule = BlockRule(
                            rule_type='domain',
                            value=canonical_domain(domain),
                            domains={canonical_domain(domain)},
                            rule_id=rule.id,
                        )
                        refreshed[mac].append(block_rule)

        self._device_rules = refreshed
        logger.info(f"Loaded rules for {len(refreshed)} devices")

    def add_app_block(self, mac: str, app_name: str) -> bool:
        """
        Block an app for a device.

        Args:
            mac: Device MAC address
            app_name: Name of app to block (e.g., 'tiktok')

        Returns:
            True if added successfully
        """
        normalized_mac = normalize_mac(mac)

        if app_name not in self._app_signatures:
            logger.warning(f"Unknown app: {app_name}")
            return False

        if normalized_mac not in self._device_rules:
            self._device_rules[normalized_mac] = []

        # Check if already blocked
        for rule in self._device_rules[normalized_mac]:
            if rule.rule_type == 'app' and rule.value == app_name:
                logger.info(f"App {app_name} already blocked for {normalized_mac}")
                return True

        block_rule = BlockRule(
            rule_type='app',
            value=app_name,
            domains=set(self._app_signatures[app_name])
        )
        self._device_rules[normalized_mac].append(block_rule)

        logger.info(f"Blocked app {app_name} for {normalized_mac}")
        return True

    def remove_app_block(self, mac: str, app_name: str) -> bool:
        """Remove app block for a device."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            return False

        original_len = len(self._device_rules[normalized_mac])
        self._device_rules[normalized_mac] = [
            rule for rule in self._device_rules[normalized_mac]
            if not (rule.rule_type == 'app' and rule.value == app_name)
        ]

        removed = len(self._device_rules[normalized_mac]) < original_len
        if removed:
            logger.info(f"Unblocked app {app_name} for {normalized_mac}")

        return removed

    def add_domain_block(self, mac: str, domain: str) -> bool:
        """Block a domain for a device."""
        domain = canonical_domain(domain)
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            self._device_rules[normalized_mac] = []

        # Check if already blocked
        for rule in self._device_rules[normalized_mac]:
            if rule.rule_type == 'domain' and rule.value == domain:
                return True

        block_rule = BlockRule(
            rule_type='domain',
            value=domain,
            domains={domain}
        )
        self._device_rules[normalized_mac].append(block_rule)

        logger.info(f"Blocked domain {domain} for {normalized_mac}")
        return True

    def remove_domain_block(self, mac: str, domain: str) -> bool:
        """Remove domain block for a device."""
        domain = canonical_domain(domain)
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            return False

        original_len = len(self._device_rules[normalized_mac])
        self._device_rules[normalized_mac] = [
            rule for rule in self._device_rules[normalized_mac]
            if not (rule.rule_type == 'domain' and rule.value == domain)
        ]

        return len(self._device_rules[normalized_mac]) < original_len

    def should_block(self, mac: str, domain: str) -> Optional[str]:
        """
        Check if a domain should be blocked for a device.

        Args:
            mac: Device MAC address
            domain: Domain being accessed

        Returns:
            Reason for blocking (app/domain name) or None if allowed
        """
        match = self.match(mac, domain)
        return match.value if match else None

    def match(self, mac: str, domain: str) -> PolicyMatch | None:
        """Return the exact rule responsible for a domain policy decision."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            return None

        domain_lower = canonical_domain(domain)

        for rule in self._device_rules[normalized_mac]:
            for pattern in rule.domains:
                # Handle wildcard patterns (e.g., *.tiktok.com)
                if pattern.startswith('*.'):
                    # Match pattern like *.example.com against example.com and sub.example.com
                    base_domain = pattern[2:]
                    if domain_lower == base_domain or domain_lower.endswith('.' + base_domain):
                        return PolicyMatch(
                            rule.rule_id,
                            "app_rule" if rule.rule_type == "app" else "domain_rule",
                            rule.value,
                            rule.value if rule.rule_type == "app" else None,
                        )
                elif domain_lower == pattern.lower():
                    return PolicyMatch(
                        rule.rule_id,
                        "app_rule" if rule.rule_type == "app" else "domain_rule",
                        rule.value,
                        rule.value if rule.rule_type == "app" else None,
                    )

        return None

    def get_blocked_apps(self, mac: str) -> List[str]:
        """Get list of blocked apps for a device."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            return []

        return [
            rule.value for rule in self._device_rules[normalized_mac]
            if rule.rule_type == 'app'
        ]

    def get_blocked_domains(self, mac: str) -> List[str]:
        """Get list of blocked domains for a device."""
        normalized_mac = normalize_mac(mac)

        if normalized_mac not in self._device_rules:
            return []

        return [
            rule.value for rule in self._device_rules[normalized_mac]
            if rule.rule_type == 'domain'
        ]

    def get_available_apps(self) -> Dict[str, List[str]]:
        """Get all available apps and their domain patterns."""
        return self._app_signatures.copy()

    def clear_device_rules(self, mac: str):
        """Clear all blocking rules for a device."""
        normalized_mac = normalize_mac(mac)
        if normalized_mac in self._device_rules:
            del self._device_rules[normalized_mac]
            logger.info(f"Cleared all rules for {normalized_mac}")
