"""Device rules API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field, field_validator
from utils.domains import canonical_domain
from sqlalchemy import select, delete

from api.auth import get_current_user
from api.websocket import ws_manager, WSMessage
from db.database import get_session
from db.models import Device, DeviceRule

router = APIRouter(prefix="/devices/{mac}/rules", tags=["rules"])


# Pydantic models
class BandwidthRuleRequest(BaseModel):
    """Bandwidth limit rule request."""
    download_kbps: int = Field(..., ge=1, description="Download limit in Kbps")
    upload_kbps: int = Field(..., ge=1, description="Upload limit in Kbps")


class AppBlockRuleRequest(BaseModel):
    """App block rule request."""
    app: str = Field(..., description="App name to block (e.g., 'tiktok')")


class DomainBlockRuleRequest(BaseModel):
    """Domain block rule request."""
    domain: str = Field(..., description="Domain pattern to block")

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        return canonical_domain(value)


class RuleResponse(BaseModel):
    """Rule response model."""
    id: int
    device_id: int
    rule_type: str
    rule_value: dict
    is_active: bool
    created_at: Optional[str]


class RuleListResponse(BaseModel):
    """List of rules response."""
    rules: List[RuleResponse]
    total: int


# App state reference
_app_state = None


def set_app_state(state):
    global _app_state
    _app_state = state


def get_app_state():
    if _app_state is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized"
        )
    return _app_state


async def get_device_by_mac(mac: str) -> Device:
    """Get device from database by MAC address."""
    from utils.mac_utils import normalize_mac
    normalized_mac = normalize_mac(mac)

    async with get_session() as session:
        result = await session.execute(
            select(Device).where(Device.mac_address == normalized_mac)
        )
        device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    return device


@router.get("", response_model=RuleListResponse)
async def list_rules(mac: str, user: str = Depends(get_current_user)):
    """Get all rules for a device."""
    device = await get_device_by_mac(mac)

    async with get_session() as session:
        result = await session.execute(
            select(DeviceRule).where(DeviceRule.device_id == device.id)
        )
        rules = result.scalars().all()

    rule_list = [RuleResponse(**r.to_dict()) for r in rules]

    return RuleListResponse(rules=rule_list, total=len(rule_list))


@router.post("/bandwidth", response_model=RuleResponse)
async def create_bandwidth_rule(
    mac: str,
    rule: BandwidthRuleRequest,
    user: str = Depends(get_current_user)
):
    """Create or update bandwidth limit for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)

    async with get_session() as session:
        # Check for existing bandwidth rule
        result = await session.execute(
            select(DeviceRule).where(
                DeviceRule.device_id == device.id,
                DeviceRule.rule_type == "bandwidth"
            )
        )
        existing = result.scalar_one_or_none()

        rule_value = {
            "download_kbps": rule.download_kbps,
            "upload_kbps": rule.upload_kbps
        }

        if existing:
            existing.rule_value = rule_value
            existing.is_active = True
            db_rule = existing
        else:
            db_rule = DeviceRule(
                device_id=device.id,
                rule_type="bandwidth",
                rule_value=rule_value,
                is_active=True
            )
            session.add(db_rule)

        await session.commit()
        await session.refresh(db_rule)

    # Apply bandwidth limit
    await state.traffic_controller.set_bandwidth_limit(
        mac,
        rule.download_kbps,
        rule.upload_kbps
    )

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": db_rule.to_dict()
    })

    return RuleResponse(**db_rule.to_dict())


@router.post("/block-app", response_model=RuleResponse)
async def create_app_block_rule(
    mac: str,
    rule: AppBlockRuleRequest,
    user: str = Depends(get_current_user)
):
    """Block an app for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)

    # Check if app exists
    available_apps = state.content_blocker.get_available_apps()
    if rule.app not in available_apps:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown app: {rule.app}. Available: {list(available_apps.keys())}"
        )

    async with get_session() as session:
        # Check for existing rule
        result = await session.execute(
            select(DeviceRule).where(
                DeviceRule.device_id == device.id,
                DeviceRule.rule_type == "block_app"
            )
        )
        existing_rules = result.scalars().all()

        # Check if app already blocked
        for existing in existing_rules:
            if existing.rule_value.get("app") == rule.app:
                return RuleResponse(**existing.to_dict())

        rule_value = {"app": rule.app}
        db_rule = DeviceRule(
            device_id=device.id,
            rule_type="block_app",
            rule_value=rule_value,
            is_active=True
        )
        session.add(db_rule)
        await session.commit()
        await session.refresh(db_rule)

    # Apply block
    state.content_blocker.add_app_block(mac, rule.app)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": db_rule.to_dict()
    })

    return RuleResponse(**db_rule.to_dict())


@router.post("/block-domain", response_model=RuleResponse)
async def create_domain_block_rule(
    mac: str,
    rule: DomainBlockRuleRequest,
    user: str = Depends(get_current_user)
):
    """Block a domain for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)

    async with get_session() as session:
        rule_value = {"domain": rule.domain}
        db_rule = DeviceRule(
            device_id=device.id,
            rule_type="block_domain",
            rule_value=rule_value,
            is_active=True
        )
        session.add(db_rule)
        await session.commit()
        await session.refresh(db_rule)

    # Apply block
    state.content_blocker.add_domain_block(mac, rule.domain)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": db_rule.to_dict()
    })

    return RuleResponse(**db_rule.to_dict())


@router.delete("/{rule_id}")
async def delete_rule(
    mac: str,
    rule_id: int,
    user: str = Depends(get_current_user)
):
    """Delete a rule."""
    state = get_app_state()
    device = await get_device_by_mac(mac)

    async with get_session() as session:
        result = await session.execute(
            select(DeviceRule).where(
                DeviceRule.id == rule_id,
                DeviceRule.device_id == device.id
            )
        )
        rule = result.scalar_one_or_none()

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule not found: {rule_id}"
            )

        rule_type = rule.rule_type
        rule_value = rule.rule_value

        await session.delete(rule)
        await session.commit()

    # Remove applied rule
    if rule_type == "bandwidth":
        await state.traffic_controller.remove_bandwidth_limit(mac)
    elif rule_type == "block_app":
        state.content_blocker.remove_app_block(mac, rule_value.get("app"))
    elif rule_type == "block_domain":
        state.content_blocker.remove_domain_block(mac, rule_value.get("domain"))

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "deleted",
        "device_mac": mac,
        "rule_id": rule_id
    })

    return {"status": "deleted", "rule_id": rule_id}


@router.get("/apps/available")
async def list_available_apps(user: str = Depends(get_current_user)):
    """Get list of apps that can be blocked."""
    state = get_app_state()
    apps = state.content_blocker.get_available_apps()

    return {
        "apps": [
            {"name": name, "domains": domains}
            for name, domains in apps.items()
        ]
    }
