from device import Device

def test_device_initialization():
    device = Device(ip="192.168.1.1", mac="AA-BB-CC-DD-EE-FF")
    assert device.ip == "192.168.1.1"
    assert device.mac == "AA-BB-CC-DD-EE-FF"
    assert device.name is None
    assert device.status == "offline"
    assert device.additional_macs == []
    assert device.additional_ips == []

def test_device_with_optional_fields():
    device = Device(
        ip="192.168.1.2",
        mac="11-22-33-44-55-66",
        name="Test Device",
        hostname="test-host",
        vendor="Test Vendor",
        status="online",
        additional_macs=["22-33-44-55-66-77"],
        additional_ips=["192.168.1.3"]
    )
    assert device.name == "Test Device"
    assert device.hostname == "test-host"
    assert device.vendor == "Test Vendor"
    assert device.status == "online"
    assert device.additional_macs == ["22-33-44-55-66-77"]
    assert device.additional_ips == ["192.168.1.3"]
