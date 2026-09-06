"""Canonical persisted rule identities."""

import re
from utils.domains import canonical_domain


def canonical_rule(rule_type, value):
    if rule_type == "block_domain":
        domain = canonical_domain(value["domain"])
        return domain, {"domain": domain}
    if rule_type == "block_app":
        app = value["app"].strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", app):
            raise ValueError("Invalid application identifier")
        return app, {"app": app}
    if rule_type == "bandwidth":
        limits = {key: value[key] for key in ("download_kbps", "upload_kbps")}
        if any(type(limit) is not int or limit < 1 for limit in limits.values()):
            raise ValueError("Invalid bandwidth limits")
        return "bandwidth", limits
    raise ValueError("Unknown rule type")


def rule_identity_default(context):
    values = context.get_current_parameters()
    return canonical_rule(values["rule_type"], values["rule_value"])[0]
