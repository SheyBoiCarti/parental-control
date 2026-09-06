import pytest
from pydantic import ValidationError
from core.content_blocker import BlockRule, ContentBlocker
from api.routes.rules import DomainBlockRuleRequest

MAC = "AA:BB:CC:DD:EE:01"


def test_equivalent_domain_rules_deduplicate_and_remove():
    blocker = ContentBlocker()
    blocker.add_domain_block(MAC, "*.BÜCHER.Example.")
    blocker.add_domain_block(MAC, "*.xn--bcher-kva.example")
    assert blocker.get_blocked_domains(MAC) == ["*.xn--bcher-kva.example"]
    assert blocker.should_block(MAC, "shop.BÜCHER.example.")
    assert blocker.remove_domain_block(MAC, "*.BÜCHER.EXAMPLE.")
    assert blocker.should_block(MAC, "shop.bücher.example") is None


@pytest.mark.parametrize("pattern,host,blocked", [
    ("*.example.com", "example.com", True),
    ("*.example.com", "a.b.example.com.", True),
    ("*.example.com", "notexample.com", False),
    ("example.com", "sub.example.com", False),
    ("example.com", "EXAMPLE.COM.", True),
])
def test_exact_and_wildcard_domain_boundaries(pattern, host, blocked):
    blocker = ContentBlocker()
    blocker.add_domain_block(MAC, pattern)
    assert bool(blocker.should_block(MAC, host)) == blocked


def test_api_normalizes_domains_and_rejects_globs_and_urls():
    assert DomainBlockRuleRequest(domain="*.Example.COM.").domain == "*.example.com"
    for domain in ["https://example.com", "foo?.example", "foo.*.com", "[ab].example"]:
        with pytest.raises(ValidationError):
            DomainBlockRuleRequest(domain=domain)


def test_match_identifies_the_enforced_rule_and_reason():
    blocker = ContentBlocker()
    blocker._device_rules[MAC] = [
        BlockRule(
            rule_type="domain",
            value="example.com",
            domains={"example.com"},
            rule_id=42,
        )
    ]

    match = blocker.match(MAC, "EXAMPLE.COM.")

    assert match is not None
    assert (match.rule_id, match.reason, match.app_name) == (42, "domain_rule", None)


@pytest.mark.asyncio
async def test_invalid_mac_on_rule_route_is_validation_error():
    from api.routes.rules import get_device_by_mac
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        await get_device_by_mac("invalid")
    assert error.value.status_code == 422
