"""Device rules API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Response, status
from pydantic import BaseModel, Field, field_validator
from utils.domains import canonical_domain
from utils.rules import canonical_rule
from sqlalchemy import select, delete

from api.auth import get_current_user
from api.websocket import ws_manager, WSMessage
from db.database import get_session
from db.rules import save_rule
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

    @field_validator("app")
    @classmethod
    def normalize_app(cls, value: str) -> str:
        return canonical_rule("block_app", {"app": value})[0]


class DomainBlockRuleRequest(BaseModel):
    """Domain block rule request."""
    domain: str = Field(..., description="Domain pattern to block")

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        return canonical_domain(value)


class EnforcementResponse(BaseModel):
    state: str
    last_error: Optional[str] = None
    updated_at: str


class RuleResponse(BaseModel):
    """Rule response model."""
    id: int
    device_id: int
    rule_type: str
    rule_value: dict
    is_active: bool
    created_at: Optional[str]
    validation_error: Optional[str] = None
    enforcement: EnforcementResponse


class RuleListResponse(BaseModel):
    """List of rules response."""
    rules: List[RuleResponse]
    total: int


def _rule_component(rule_type: str) -> str:
    return "bandwidth" if rule_type == "bandwidth" else "content"


def _rule_payload(rule: DeviceRule, result) -> dict:
    if rule.validation_error:
        enforcement = {
            "state": "error",
            "last_error": rule.validation_error,
            "updated_at": result.components[_rule_component(rule.rule_type)].updated_at,
        }
    elif not rule.is_active:
        enforcement = {
            "state": "inactive",
            "last_error": None,
            "updated_at": result.components[_rule_component(rule.rule_type)].updated_at,
        }
    else:
        enforcement = result.components[_rule_component(rule.rule_type)].to_dict()
    return rule.to_dict() | {"enforcement": enforcement}


def _apply_http_result(result, response: Response) -> None:
    if result.state == "error":
        raise HTTPException(
            status_code=503,
            detail={
                "code": "ENFORCEMENT_APPLY_FAILED",
                "enforcement": result.to_dict(),
            },
        )
    if result.state == "pending":
        response.status_code = status.HTTP_202_ACCEPTED


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
    try:
        normalized_mac = normalize_mac(mac)
    except ValueError as error:
        raise HTTPException(422, "Invalid MAC address") from error

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


def _validate_enforcement_target(state, device: Device, mac: str) -> None:
    if not device.ip_address:
        return
    try:
        state.arp_spoofer.validate_target(device.ip_address, mac)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error


@router.get("", response_model=RuleListResponse)
async def list_rules(mac: str, user: str = Depends(get_current_user)):
    """Get all rules for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)

    async with get_session() as session:
        result = await session.execute(
            select(DeviceRule).where(DeviceRule.device_id == device.id)
        )
        rules = result.scalars().all()

    enforcement = await state.reconciler.get_status(mac)
    rule_list = [RuleResponse(**_rule_payload(rule, enforcement)) for rule in rules]

    return RuleListResponse(rules=rule_list, total=len(rule_list))


@router.post("/bandwidth", response_model=RuleResponse)
async def create_bandwidth_rule(
    mac: str,
    rule: BandwidthRuleRequest,
    response: Response,
    user: str = Depends(get_current_user)
):
    """Create or update bandwidth limit for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)
    _validate_enforcement_target(state, device, mac)

    db_rule = await save_rule(device.id, "bandwidth", {"download_kbps": rule.download_kbps, "upload_kbps": rule.upload_kbps})

    result = await state.reconciler.reconcile(mac)
    payload = _rule_payload(db_rule, result)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": payload,
    })

    _apply_http_result(result, response)
    return RuleResponse(**payload)


@router.post("/block-app", response_model=RuleResponse)
async def create_app_block_rule(
    mac: str,
    rule: AppBlockRuleRequest,
    response: Response,
    user: str = Depends(get_current_user)
):
    """Block an app for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)
    _validate_enforcement_target(state, device, mac)

    # Check if app exists
    available_apps = state.content_blocker.get_available_apps()
    if rule.app not in available_apps:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown app: {rule.app}. Available: {list(available_apps.keys())}"
        )

    db_rule = await save_rule(device.id, "block_app", {"app": rule.app})

    # Apply block
    await state.content_blocker._load_device_rules()
    result = await state.reconciler.reconcile(mac)
    payload = _rule_payload(db_rule, result)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": payload,
    })

    _apply_http_result(result, response)
    return RuleResponse(**payload)


@router.post("/block-domain", response_model=RuleResponse)
async def create_domain_block_rule(
    mac: str,
    rule: DomainBlockRuleRequest,
    response: Response,
    user: str = Depends(get_current_user)
):
    """Block a domain for a device."""
    state = get_app_state()
    device = await get_device_by_mac(mac)
    _validate_enforcement_target(state, device, mac)

    db_rule = await save_rule(device.id, "block_domain", {"domain": rule.domain})

    # Apply block
    await state.content_blocker._load_device_rules()
    result = await state.reconciler.reconcile(mac)
    payload = _rule_payload(db_rule, result)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "created",
        "device_mac": mac,
        "rule": payload,
    })

    _apply_http_result(result, response)
    return RuleResponse(**payload)


@router.delete("/{rule_id}")
async def delete_rule(
    mac: str,
    rule_id: int,
    response: Response,
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
        rule.is_active = False
        await session.commit()

    if rule_type in {"block_app", "block_domain"}:
        await state.content_blocker._load_device_rules()
    result = await state.reconciler.reconcile(mac)

    if result.state == "error":
        async with get_session() as session:
            retained = (await session.execute(
                select(DeviceRule).where(
                    DeviceRule.id == rule_id,
                    DeviceRule.device_id == device.id,
                )
            )).scalar_one_or_none()
            if retained is not None:
                retained.is_active = True
                await session.commit()
        if rule_type in {"block_app", "block_domain"}:
            await state.content_blocker._load_device_rules()
        _apply_http_result(result, response)

    async with get_session() as session:
        await session.execute(delete(DeviceRule).where(
            DeviceRule.id == rule_id,
            DeviceRule.device_id == device.id,
        ))
        await session.commit()

    _apply_http_result(result, response)

    # Broadcast update
    await ws_manager.broadcast_rule_update({
        "action": "deleted",
        "device_mac": mac,
        "rule_id": rule_id
    })

    return {
        "status": "deleted",
        "rule_id": rule_id,
        "enforcement": result.to_dict(),
    }


@router.get("/apps/available")
async def list_available_apps(user: str = Depends(get_current_user)):
    """Get list of apps that can be blocked."""
    state = get_app_state()
    return {"apps": state.content_blocker.get_available_app_records()}
