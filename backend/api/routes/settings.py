"""Settings API routes."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy import select

from api.auth import COOKIE_NAME, get_auth_service, get_current_user
from db.database import get_session
from db.models import Setting

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingResponse(BaseModel):
    """Setting response model."""
    key: str
    value: Optional[str]


class SettingsListResponse(BaseModel):
    """All settings response."""
    settings: dict


class PasswordChangeRequest(BaseModel):
    """Password change request."""
    current_password: str
    new_password: str


def reserved_key(key: str) -> bool:
    key = key.lower()
    return any(part in key for part in ("password", "credential", "session", "csrf", "token", "secret")) or key.startswith("auth_")


# App state reference
_app_state = None


def set_app_state(state):
    global _app_state
    _app_state = state


def get_app_state():
    if _app_state is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return _app_state


@router.get("", response_model=SettingsListResponse)
async def get_settings(user: str = Depends(get_current_user)):
    """Get all settings."""
    async with get_session() as session:
        result = await session.execute(select(Setting))
        settings = result.scalars().all()

    return SettingsListResponse(
        settings={s.key: s.value for s in settings if not reserved_key(s.key)}
    )


@router.get("/{key}", response_model=SettingResponse)
async def get_setting(key: str, user: str = Depends(get_current_user)):
    """Get a specific setting."""
    if reserved_key(key):
        raise HTTPException(404, "Setting not found")
    async with get_session() as session:
        result = await session.execute(
            select(Setting).where(Setting.key == key)
        )
        setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting not found: {key}")

    return SettingResponse(key=setting.key, value=setting.value)


@router.put("/{key}")
async def update_setting(
    key: str,
    value: str,
    user: str = Depends(get_current_user)
):
    """Update a setting."""
    if reserved_key(key):
        raise HTTPException(422, "Reserved setting key")
    async with get_session() as session:
        result = await session.execute(
            select(Setting).where(Setting.key == key)
        )
        setting = result.scalar_one_or_none()

        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            session.add(setting)

        await session.commit()

    return {"status": "updated", "key": key}


@router.post("/password")
async def change_password(
    body: PasswordChangeRequest,
    request: Request,
    response: Response,
    user: str = Depends(get_current_user)
):
    """Change the admin password."""
    try:
        await get_auth_service(request).change_password(body.current_password, body.new_password)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    response.delete_cookie(COOKIE_NAME, path="/", secure=request.url.scheme == "https", httponly=True, samesite="strict")
    return {"status": "password_changed"}


@router.get("/network/info")
async def get_network_info(user: str = Depends(get_current_user)):
    """Get network configuration information."""
    state = get_app_state()

    return {
        "interface": state.device_manager.interface,
        "local_mac": state.device_manager.local_mac,
        "gateway_ip": state.device_manager.gateway_ip,
        "gateway_mac": state.device_manager.gateway_mac,
        "subnet": state.device_manager.subnet,
        "arp_spoof_active": state.arp_spoofer._running,
        "active_spoof_targets": len(state.arp_spoofer.active_targets),
        "packet_analyzer_running": state.packet_analyzer._running
    }
