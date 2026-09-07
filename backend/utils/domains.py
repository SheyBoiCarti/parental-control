"""Canonical domain patterns shared by catalog, API and matcher."""

import re

def canonical_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    wildcard = value.startswith("*.")
    domain = value[2:] if wildcard else value
    domain = domain.encode("idna").decode("ascii")
    if len(domain) > 253 or not domain or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in domain.split(".")
    ):
        raise ValueError("Expected a domain or leading wildcard domain")
    return ("*." if wildcard else "") + domain


