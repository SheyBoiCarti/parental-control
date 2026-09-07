import pytest
from core.arp_spoofer import ARPSpoofer


@pytest.mark.parametrize("ip,mac", [
    ("192.0.2.1", "AA:BB:CC:DD:EE:03"),
    ("192.0.2.3", "aa:bb:cc:dd:ee:01"),
    ("192.0.2.3", "AA:BB:CC:DD:EE:02"),
    ("224.0.0.1", "AA:BB:CC:DD:EE:03"),
    ("127.0.0.1", "AA:BB:CC:DD:EE:03"),
])
def test_protected_or_nonunicast_target_never_sends_packets(monkeypatch, ip, mac):
    spoofer = ARPSpoofer("eth0", "192.0.2.1", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
    sent = []
    monkeypatch.setattr(spoofer, "_send_spoof_packets", sent.append)
    with pytest.raises(ValueError):
        spoofer.add_target(ip, mac)
    assert not spoofer.active_targets
    assert not sent


def test_valid_target_is_staged_without_interception_before_service_start(monkeypatch):
    spoofer = ARPSpoofer(
        "eth0", "192.0.2.1", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"
    )
    sent = []
    monkeypatch.setattr(spoofer, "_send_spoof_packets", sent.append)

    assert spoofer.add_target("192.0.2.3", "AA:BB:CC:DD:EE:03")

    assert spoofer.active_targets == {"AA:BB:CC:DD:EE:03"}
    assert sent == []


@pytest.mark.parametrize("ip", ["192.0.2.2", "198.51.100.3"])
def test_appliance_ip_and_addresses_outside_selected_subnet_are_rejected(ip):
    spoofer = ARPSpoofer(
        "eth0",
        "192.0.2.1",
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
        local_ip="192.0.2.2",
        network_subnet="192.0.2.0/24",
    )

    with pytest.raises(ValueError):
        spoofer.validate_target(ip, "AA:BB:CC:DD:EE:03")


@pytest.mark.asyncio
async def test_address_update_cannot_retarget_gateway(monkeypatch):
    spoofer = ARPSpoofer("eth0", "192.0.2.1", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
    monkeypatch.setattr(spoofer, "_send_spoof_packets", lambda target: None)
    mac = "AA:BB:CC:DD:EE:03"
    spoofer.add_target("192.0.2.3", mac)
    with pytest.raises(ValueError):
        await spoofer.update_target_ip(mac, "192.0.2.1")
    assert spoofer._targets[mac].ip_address == "192.0.2.3"


@pytest.mark.asyncio
async def test_api_rejects_gateway_before_saving_monitoring(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from fastapi import HTTPException, Response
    from api.routes import devices
    manager = SimpleNamespace(
        get_device_by_mac=AsyncMock(return_value=SimpleNamespace(ip_address="192.0.2.1")),
        update_device=AsyncMock(),
    )
    monkeypatch.setattr(devices, "_app_state", SimpleNamespace(device_manager=manager,
        arp_spoofer=ARPSpoofer("eth0", "192.0.2.1", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")))
    with pytest.raises(HTTPException) as error:
        await devices.start_monitoring(
            "AA:BB:CC:DD:EE:03", response=Response(), user="admin"
        )
    assert error.value.status_code == 422
    manager.update_device.assert_not_awaited()
