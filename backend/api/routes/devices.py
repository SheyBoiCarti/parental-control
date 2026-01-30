"""Device management API routes."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field

from api.auth import get_current_user
from api.websocket import ws_manager, WSMessage

router = APIRouter(prefix="/devices", tags=["devices"])


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


@router.get("", response_model=DeviceListResponse)
async def list_devices(user: str = Depends(get_current_user)):
    """Get all discovered devices."""
    state = get_app_state()
    devices = await state.device_manager.get_all_devices()

    device_list = [DeviceResponse(**d.to_dict()) for d in devices]

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

    return DeviceResponse(**device.to_dict())


@router.patch("/{mac}", response_model=DeviceResponse)
async def update_device(
    mac: str,
    update: DeviceUpdateRequest,
    user: str = Depends(get_current_user)
):
    """Update device properties."""
    state = get_app_state()

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

    # Handle blocking state change
    if update.is_blocked is not None:
        if update.is_blocked:
            await state.device_blocker.block_device(mac)
        else:
            await state.device_blocker.unblock_device(mac)

    # Handle monitoring state change
    if update.is_monitored is not None:
        if update.is_monitored and device.ip_address:
            state.arp_spoofer.add_target(device.ip_address, mac)
        elif not update.is_monitored:
            state.arp_spoofer.remove_target(mac)

    # Broadcast update
    await ws_manager.broadcast_device_update(device.to_dict())

    return DeviceResponse(**device.to_dict())


@router.post("/{mac}/block")
async def block_device(mac: str, user: str = Depends(get_current_user)):
    """Block a device's network access."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    # Update database
    device = await state.device_manager.update_device(mac, is_blocked=True)

    # Apply block
    success = await state.device_blocker.block_device(mac)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to block device"
        )

    # Broadcast update
    await ws_manager.broadcast_device_update(device.to_dict())

    return {"status": "blocked", "mac": mac}


@router.delete("/{mac}/block")
async def unblock_device(mac: str, user: str = Depends(get_current_user)):
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

    # Remove block
    success = await state.device_blocker.unblock_device(mac)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unblock device"
        )

    # Broadcast update
    await ws_manager.broadcast_device_update(device.to_dict())

    return {"status": "unblocked", "mac": mac}


@router.post("/{mac}/monitor")
async def start_monitoring(mac: str, user: str = Depends(get_current_user)):
    """Start monitoring a device (ARP spoofing for traffic inspection)."""
    state = get_app_state()

    device = await state.device_manager.get_device_by_mac(mac)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {mac}"
        )

    if not device.ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device has no known IP address"
        )

    # Update database
    device = await state.device_manager.update_device(mac, is_monitored=True)

    # Start ARP spoofing for this device
    state.arp_spoofer.add_target(device.ip_address, mac)

    # Broadcast update
    await ws_manager.broadcast_device_update(device.to_dict())

    return {"status": "monitoring", "mac": mac}


@router.delete("/{mac}/monitor")
async def stop_monitoring(mac: str, user: str = Depends(get_current_user)):
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

    # Stop ARP spoofing
    state.arp_spoofer.remove_target(mac)

    # Broadcast update
    await ws_manager.broadcast_device_update(device.to_dict())

    return {"status": "stopped", "mac": mac}


@router.post("/scan")
async def trigger_scan(user: str = Depends(get_current_user)):
    """Trigger an immediate network scan."""
    state = get_app_state()

    discovered = await state.device_manager.scan_network()
    devices = await state.device_manager.update_devices_from_scan(discovered)

    device_list = [DeviceResponse(**d.to_dict()) for d in devices]

    # Broadcast full device list
    await ws_manager.broadcast_devices_list([d.to_dict() for d in devices])

    return DeviceListResponse(
        devices=device_list,
        total=len(device_list)
    )
