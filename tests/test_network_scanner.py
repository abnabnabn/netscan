import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from network_scanner import (
    add_new_device, update_device, detect_multiple_mac_ip,
    find_matching_device, _update_existing_devices, _add_new_devices,
    _mark_offline_devices, populate_vendor_and_name, get_vendor_from_mac,
    _populate_additional_macs_ips, validate_scan_results
)

def test_add_new_device():
    current_devices = {}
    add_new_device(current_devices, "host1", "AA-BB", "1.1.1.1")
    assert "AA-BB:1.1.1.1" in current_devices
    assert current_devices["AA-BB:1.1.1.1"]["hostname"] == "host1"

def test_update_device():
    current_devices = {"AA-BB:1.1.1.1": {"hostname": "old", "ip": "1.1.1.1", "mac": "AA-BB"}}
    update_device(current_devices, "new", "AA-BB", "1.1.1.1")
    assert current_devices["AA-BB:1.1.1.1"]["hostname"] == "new"

def test_detect_multiple_mac_ip():
    current_devices = {
        "M1:I1": {"mac": "M1", "ip": "I1"},
        "M1:I2": {"mac": "M1", "ip": "I2"},
        "M2:I3": {"mac": "M2", "ip": "I3"},
        "M3:I3": {"mac": "M3", "ip": "I3"},
    }
    detect_multiple_mac_ip(current_devices)
    assert current_devices["M1:I1"]["multiple_mac"] is True
    assert current_devices["M1:I2"]["multiple_mac"] is True
    assert current_devices["M2:I3"]["multiple_mac"] is False
    assert current_devices["M2:I3"]["multiple_ip"] is True
    assert current_devices["M3:I3"]["multiple_mac"] is False
    assert current_devices["M3:I3"]["multiple_ip"] is True

@patch("network_scanner.get_vendor_from_mac")
def test_find_matching_device(mock_vendor):
    mock_vendor.return_value = "Vendor1"
    json_list = [{"ip": "1.1.1.1", "mac": "AA-BB", "hostname": "h1", "vendor": "Vendor1"}]
    json_dict = {"1.1.1.1": json_list[0]}
    
    # 1. IP and MAC match
    curr = {"ip": "1.1.1.1", "mac": "AA-BB", "hostname": "h1"}
    match = find_matching_device(curr, json_list, json_dict, {"K": curr})
    assert match == json_list[0]
    
    # 2. MAC match only
    curr = {"ip": "1.1.1.2", "mac": "AA-BB", "hostname": "h2"}
    match = find_matching_device(curr, json_list, json_dict, {"K": curr})
    assert match == json_list[0]

@patch("network_scanner.get_vendor_from_mac")
def test_find_matching_device_hostname_match(mock_vendor):
    mock_vendor.return_value = "Vendor1"
    json_list = [{"ip": "1.1.1.1", "mac": "AA-BB", "hostname": "h1", "vendor": "Vendor1"}]
    json_dict = {"1.1.1.1": json_list[0]}
    
    # Hostname and Vendor match (new IP)
    curr = {"ip": "1.1.1.2", "mac": "CC-DD", "hostname": "h1"}
    match = find_matching_device(curr, json_list, json_dict, {"K": curr})
    assert match == json_list[0]

@patch("network_scanner.get_vendor_from_mac")
def test_find_matching_device_non_unique_hostname(mock_vendor):
    mock_vendor.return_value = "Vendor1"
    json_list = [{"ip": "1.1.1.1", "mac": "AA-BB", "hostname": "h1", "vendor": "Vendor1"}]
    json_dict = {"1.1.1.1": json_list[0]}
    
    # Hostname is NOT unique in current scan
    curr1 = {"ip": "1.1.1.1", "mac": "AA-BB", "hostname": "h1"}
    curr2 = {"ip": "1.1.1.2", "mac": "CC-DD", "hostname": "h1"}
    current_devices = {"K1": curr1, "K2": curr2}
    
    match = find_matching_device(curr1, json_list, json_dict, current_devices)
    # Should still match because IP/MAC match is checked FIRST
    assert match == json_list[0]
    
    # Now try with only hostname match (different IP/MAC)
    curr3 = {"ip": "1.1.1.3", "mac": "EE-FF", "hostname": "h1"}
    match = find_matching_device(curr3, json_list, json_dict, current_devices)
    assert match is None # Because h1 is not unique

def test_mark_offline_devices():
    json_list = [
        {"ip": "1.1.1.1", "status": "online"},
        {"ip": "1.1.1.2", "status": "online"}
    ]
    current_devices = {"K": {"ip": "1.1.1.1"}}
    updated = _mark_offline_devices(current_devices, json_list)
    assert updated is True
    assert json_list[0]["status"] == "online"
    assert json_list[1]["status"] == "offline"

def test_update_existing_devices():
    current_devices = {
        "M1:I1": {"ip": "I1", "mac": "M1", "hostname": "new_h", "processed": False}
    }
    json_list = [{"ip": "I1", "mac": "M1", "hostname": "old_h", "status": "online"}]
    json_dict = {"I1": json_list[0]}
    
    updated = _update_existing_devices(current_devices, json_dict, json_list)
    assert updated is True
    assert json_list[0]["hostname"] == "new_h"
    assert current_devices["M1:I1"]["processed"] is True

@patch("network_scanner.get_vendor_from_mac")
def test_update_existing_devices_mac_changed(mock_vendor):
    mock_vendor.return_value = "Vendor1"
    current_devices = {
        "M2:I1": {"ip": "I1", "mac": "M2", "hostname": "h1", "processed": False}
    }
    json_list = [{"ip": "I1", "mac": "M1", "hostname": "h1", "status": "online", "additional_macs": [], "vendor": "Vendor1"}]
    json_dict = {"I1": json_list[0]}
    
    updated = _update_existing_devices(current_devices, json_dict, json_list)
    assert updated is True
    assert json_list[0]["mac"] == "M2"
    assert "M1" in json_list[0]["additional_macs"]

def test_update_existing_devices_ip_changed():
    current_devices = {
        "M1:I2": {"ip": "I2", "mac": "M1", "hostname": "h1", "processed": False}
    }
    # Match by MAC but IP is different
    json_list = [{"ip": "I1", "mac": "M1", "hostname": "h1", "status": "offline"}]
    json_dict = {"I1": json_list[0]}
    
    updated = _update_existing_devices(current_devices, json_dict, json_list)
    assert updated is True
    assert json_list[0]["ip"] == "I2"
    assert json_list[0]["status"] == "online"

def test_add_new_devices():
    current_devices = {
        "M1:I1": {"ip": "I1", "mac": "M1", "hostname": "h1", "processed": False, "multiple_ip": False}
    }
    json_list = []
    updated = _add_new_devices(current_devices, json_list)
    assert updated is True
    assert len(json_list) == 1
    assert json_list[0]["ip"] == "I1"
    assert json_list[0]["status"] == "online"

def test_populate_additional_macs_ips():
    current_devices = {
        "M2:I1": {"ip": "I1", "mac": "M2"},
        "M1:I2": {"ip": "I2", "mac": "M1"}
    }
    json_list = [
        {"ip": "I1", "mac": "M1", "status": "online", "additional_macs": []},
        {"ip": "I3", "mac": "M1", "status": "online", "additional_ips": []}
    ]
    updated = _populate_additional_macs_ips(current_devices, json_list)
    assert updated is True
    assert "M2" in json_list[0]["additional_macs"]
    assert "I2" in json_list[1]["additional_ips"]

def test_validate_scan_results(caplog):
    current_list = [{"ip": "1.1.1.1", "mac": "M1"}]
    json_list = [{"ip": "1.1.1.2", "mac": "M2", "status": "online"}]
    with caplog.at_level("ERROR"):
        validate_scan_results(current_list, json_list)
        assert "Validation Error" in caplog.text
        assert "1.1.1.1" in caplog.text

def test_update_device_not_found(caplog):
    current_devices = {}
    with caplog.at_level("WARNING"):
        update_device(current_devices, "new", "AA-BB", "1.1.1.1")
        assert "Attempted to update non-existent device" in caplog.text

@patch("network_scanner.get_router")
@patch("network_scanner.load_device_data")
@patch("network_scanner.save_device_data")
@patch("network_scanner.populate_vendor_and_name")
@patch("network_scanner.config")
def test_run_scan(mock_config, mock_populate, mock_save, mock_load, mock_get_router):
    mock_config.general.get.return_value = "fake.json"
    mock_router = MagicMock()
    mock_get_router.return_value = mock_router
    mock_router.get_device_data.return_value = [{"ip": "1.1.1.1", "mac": "M1", "hostname": "h1"}]
    # Return NEW lists for each call to avoid them being the same object
    mock_load.side_effect = [[], []]
    
    from network_scanner import run_scan
    run_scan()
    
    mock_save.assert_called_once()
    # The saved data should have 1 device
    saved_list = mock_save.call_args[0][0]
    assert len(saved_list) == 1
    assert saved_list[0]["ip"] == "1.1.1.1"

@patch("network_scanner.get_router")
@patch("network_scanner.load_device_data")
@patch("network_scanner.save_device_data")
@patch("network_scanner.populate_vendor_and_name")
@patch("network_scanner.config")
def test_run_scan_no_changes(mock_config, mock_populate, mock_save, mock_load, mock_get_router):
    mock_config.general.get.return_value = "fake.json"
    mock_router = MagicMock()
    mock_get_router.return_value = mock_router
    # Current matches existing
    mock_router.get_device_data.return_value = [{"ip": "1.1.1.1", "mac": "M1", "hostname": "h1"}]
    # Must include ALL fields that are added during processing
    existing = [{
        "ip": "1.1.1.1", "mac": "M1", "hostname": "h1", "status": "online", 
        "last_seen": "", "additional_macs": [], "additional_ips": []
    }]
    import copy
    mock_load.side_effect = [copy.deepcopy(existing), copy.deepcopy(existing)]
    
    from network_scanner import run_scan
    run_scan()
    
    mock_save.assert_not_called()

@patch("network_scanner.run_scan")
@patch("network_scanner.MacLookup")
@patch("network_scanner.config")
@patch("sys.argv", ["network_scanner.py", "--debug", "--update-mac-db"])
def test_network_scanner_main(mock_config, mock_mac_lookup, mock_run_scan):
    from network_scanner import main
    # Ensure config has the expected attributes to avoid AttributeErrors
    mock_config.asus_router.router_ip = "127.0.0.1"
    main()
    mock_run_scan.assert_called_once()
    mock_mac_lookup.return_value.update_vendors.assert_called_once()

@patch("network_scanner.MacLookup")
def test_get_vendor_from_mac(mock_mac_lookup):
    mock_instance = mock_mac_lookup.return_value
    mock_instance.lookup.return_value = "Test Vendor"
    assert get_vendor_from_mac("AA:BB:CC") == "Test Vendor"
    
    mock_instance.lookup.side_effect = KeyError()
    assert get_vendor_from_mac("UNKNOWN") is None

@patch("network_scanner.get_vendor_from_mac")
def test_populate_vendor_and_name(mock_vendor):
    mock_vendor.return_value = "VendorX"
    json_list = [{"mac": "AA-BB", "hostname": "hostX"}]
    populate_vendor_and_name(json_list)
    assert json_list[0]["vendor"] == "VendorX"
    assert json_list[0]["name"] == "hostX"
    
    json_list = [{"mac": "CC-DD", "hostname": None}]
    populate_vendor_and_name(json_list)
    assert json_list[0]["name"] == "VendorX"
