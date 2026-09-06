"""Device management API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Response, status
from pydantic import BaseModel, Field

from api.auth import get_current_user
from api.websocket import ws_manager, WSMessage

router = APIRouter(prefix="/devices", tags=["devices"])


class EnforcementComponentResponse(BaseModel):
    state: str
    last_error: Optional[str] = None
    updated_at: str


class DeviceEnforcementResponse(EnforcementComponentResponse):
    components: dict[str, EnforcementComponentResponse]


# Pydantic models for request/response
class DeviceResponse(BaseModel):
    """Device response model."""
    id: int
    mac_address: str
    ip_address: Optional[str]
    hostname: Optional[str]
    vendor: Optional[str]
    friendly_name: str
    is_monitored: bool
    is_blocked: bool
    first_seen: Optional[str]
    last_seen: Optional[str]
    is_online: bool
    enforcement: DeviceEnforcementResponse


class DeviceUpdateRequest(BaseModel):
    """Device update request model."""
    friendly_name: Optional[str] = None
    is_monitored: Optional[bool] = None
    is_blocked: Optional[bool] = None


class DeviceListResponse(BaseModel):
    """List of devices response."""
    devices: List[DeviceResponse]
    total: int


# Store reference to app state (set by main.py)
_app_state = None


def set_app_state(state):
    """Set the app state reference."""
    global _app_state
    _app_state = state


def get_app_state():
    """Get the app state."""
    if _app_state is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized"
        )
    return _app_state


def _device_payload(device, result) -> dict:
    return device.to_dict() | {"enforcement": result.to_dict()}


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


@router.get("", response_model=DeviceListResponse)
async def list_devices(user: str = Depends(get_current_user)):
    """Get all discovered devices."""
    state = get_app_state()
    devices = await state.device_manager.get_all_devices()

    device_list = []
    for device in devices:
        enforcement = await state.reconciler.get_status(device.mac_address)
        device_list.append(DeviceResponse(**_device_payload(device, enforcement)))

    return DeviceListResponse(
        devices=device_list,
        total=len(device_list)
    )


@router.get("/{mac}", response_model=DeviceResponse)
async def get_device(mac: str, user: str = Depends(get_current_user)):
    """Get a specific device by MAC address."""
    state = get_app_state()
    device = await state.device_manager.get_device_by_mac(mac)

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    enforcement = await state.reconciler.get_status(device.mac_address)
    return DeviceResponse(**_device_payload(device, enforcement))


@router.patch("/{mac}", response_model=DeviceResponse)
async def update_device(
    mac: str,
    update: DeviceUpdateRequest,
    response: Response,
    user: str = Depends(get_current_user)
):
    """Update device properties."""
    state = get_app_state()

    if update.is_monitored or update.is_blocked:
        current = await state.device_manager.get_device_by_mac(mac)
        if current is None:
            raise HTTPException(404, "Device not found")
        if current.ip_address:
            try:
                state.arp_spoofer.validate_target(current.ip_address, mac)
            except ValueError as error:
                raise HTTPException(422, str(error)) from error

    device = await state.device_manager.update_device(
        mac=mac,
        friendly_name=update.friendly_name,
        is_monitored=update.is_monitored,
        is_blocked=update.is_blocked
    )

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    if update.is_blocked is not None or update.is_monitored is not None:
        result = await state.reconciler.reconcile(mac)
    else:
        result = await state.reconciler.get_status(mac)
    payload = _device_payload(device, result)

    # Broadcast update
    await ws_manager.broadcast_device_update(payload)

    _apply_http_result(result, response)
    return DeviceResponse(**payload)


@router.post("/{mac}/block")
async def block_device(
    mac: str,
    response: Response,
    user: str = Depends(get_current_user),
):
    """Block a device's network access."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    if device.ip_address:
        try:
            state.arp_spoofer.validate_target(device.ip_address, mac)
        except ValueError as error:
            raise HTTPException(422, str(error)) from error

    device = await state.device_manager.update_device(mac, is_blocked=True)
    result = await state.reconciler.reconcile(mac)
    payload = _device_payload(device, result)

    # Broadcast update
    await ws_manager.broadcast_device_update(payload)

    _apply_http_result(result, response)
    return {"status": "blocked", "mac": mac, "enforcement": result.to_dict()}


@router.delete("/{mac}/block")
async def unblock_device(
    mac: str,
    response: Response,
    user: str = Depends(get_current_user),
):
    """Unblock a device's network access."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    # Update database
    device = await state.device_manager.update_device(mac, is_blocked=False)

    result = await state.reconciler.reconcile(mac)
    payload = _device_payload(device, result)

    # Broadcast update
    await ws_manager.broadcast_device_update(payload)

    _apply_http_result(result, response)
    return {"status": "unblocked", "mac": mac, "enforcement": result.to_dict()}


@router.post("/{mac}/monitor")
async def start_monitoring(
    mac: str,
    response: Response,
    user: str = Depends(get_current_user),
):
    """Start monitoring a device (ARP spoofing for traffic inspection)."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    if device.ip_address:
        try:
            state.arp_spoofer.validate_target(device.ip_address, mac)
        except ValueError as error:
            raise HTTPException(422, str(error)) from error

    # Update database
    device = await state.device_manager.update_device(mac, is_monitored=True)

    result = await state.reconciler.reconcile(mac)
    payload = _device_payload(device, result)

    # Broadcast update
    await ws_manager.broadcast_device_update(payload)

    _apply_http_result(result, response)
    return {"status": "monitoring", "mac": mac, "enforcement": result.to_dict()}


@router.delete("/{mac}/monitor")
async def stop_monitoring(
    mac: str,
    response: Response,
    user: str = Depends(get_current_user),
):
    """Stop monitoring a device."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    # Update database
    device = await state.device_manager.update_device(mac, is_monitored=False)

    result = await state.reconciler.reconcile(mac)
    payload = _device_payload(device, result)

    # Broadcast update
    await ws_manager.broadcast_device_update(payload)

    _apply_http_result(result, response)
    return {"status": "stopped", "mac": mac, "enforcement": result.to_dict()}


@router.post("/scan")
async def trigger_scan(user: str = Depends(get_current_user)):
    """Trigger an immediate network scan."""
    state = get_app_state()

    try:
        discovered = await state.device_manager.scan_network()
    except RuntimeError as error:
        raise HTTPException(503, "Network scan failed; saved devices are unchanged") from error
    devices = await state.device_manager.update_devices_from_scan(discovered)

    device_list = []
    payloads = []
    for device in devices:
        enforcement = await state.reconciler.reconcile(device.mac_address)
        payload = _device_payload(device, enforcement)
        payloads.append(payload)
        device_list.append(DeviceResponse(**payload))

    # Broadcast full device list
    await ws_manager.broadcast_devices_list(payloads)

    return DeviceListResponse(
        devices=device_list,
        total=len(device_list)
    )
