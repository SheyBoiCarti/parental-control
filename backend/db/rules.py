"""Atomic canonical rule writes."""

from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert
from db.database import get_session
from db.models import DeviceRule
from utils.rules import canonical_rule


async def save_rule(device_id: int, rule_type: str, value: dict) -> DeviceRule:
    identity, value = canonical_rule(rule_type, value)
    async with get_session() as session:
        await session.execute(insert(DeviceRule).values(
            device_id=device_id, rule_type=rule_type, canonical_value=identity,
            rule_value=value, is_active=True,
        ).on_conflict_do_update(
            index_elements=["device_id", "rule_type", "canonical_value"],
            set_={"rule_value": value, "is_active": True, "validation_error": None,
                  "updated_at": datetime.now(timezone.utc).replace(tzinfo=None)},
        ))
        result = await session.execute(select(DeviceRule).where(
            DeviceRule.device_id == device_id, DeviceRule.rule_type == rule_type,
            DeviceRule.canonical_value == identity,
        ))
        return result.scalar_one()
