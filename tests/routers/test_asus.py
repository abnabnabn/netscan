import pytest
from unittest.mock import MagicMock, patch
from routers.asus import AsusRouter
from dynaconf import Dynaconf

@pytest.fixture
def mock_config():
    # Use a mock that responds to .get()
    mock = MagicMock()
    conf_data = {
        "router_ip": "192.168.1.1",
        "router_user": "admin",
        "ssh_timeout": 5
    }
    mock.get.side_effect = lambda key, default=None: conf_data.get(key, default)
    return mock

@pytest.fixture
def asus_router(mock_config):
    return AsusRouter(mock_config)

def test_asus_router_init(asus_router, mock_config):
    assert asus_router.router_ip == "192.168.1.1"
    assert asus_router.router_user == "admin"
    assert asus_router.ssh_timeout == 5

def test_parse_arp_line(asus_router):
    line = "hostname (192.168.1.10) at AA:BB:CC:DD:EE:FF [ether] on br0"
    parsed = asus_router._parse_arp_line(line)
    assert parsed == {"ip": "192.168.1.10", "mac": "AA-BB-CC-DD-EE-FF", "hostname": "hostname"}

    line_no_hostname = "? (192.168.1.11) at 11:22:33:44:55:66 on br0"
    parsed = asus_router._parse_arp_line(line_no_hostname)
    assert parsed == {"ip": "192.168.1.11", "mac": "11-22-33-44-55-66", "hostname": None}

    line_incomplete = "? (192.168.1.12) at <incomplete> on br0"
    assert asus_router._parse_arp_line(line_incomplete) is None

def test_parse_dhcp_line(asus_router):
    line = "123456789 AA:BB:CC:DD:EE:FF 192.168.1.10 hostname 01:AA:BB:CC:DD:EE:FF"
    parsed = asus_router._parse_dhcp_line(line)
    assert parsed == {"ip": "192.168.1.10", "mac": "AA-BB-CC-DD-EE-FF", "hostname": "hostname"}

    line_no_hostname = "123456789 11:22:33:44:55:66 192.168.1.11 * 01:11:22:33:44:55:66"
    parsed = asus_router._parse_dhcp_line(line_no_hostname)
    assert parsed == {"ip": "192.168.1.11", "mac": "11-22-33-44-55-66", "hostname": None}

def test_parse_dhcp_leases_isc(asus_router):
    dhcp_output = """
    lease 192.168.1.50 {
      starts 1 2023/01/01 00:00:00;
      ends 1 2023/01/01 12:00:00;
      hardware ethernet 00:11:22:33:44:55;
      uid "\001\000\021\"4U";
      client-hostname "isc-device";
    }
    """
    devices = asus_router._parse_dhcp_leases(dhcp_output)
    assert len(devices) == 1
    assert devices[0] == {"ip": "192.168.1.50", "mac": "00-11-22-33-44-55", "hostname": "isc-device"}

@patch("routers.asus.SSHClient")
def test_get_device_data(mock_ssh_class, asus_router):
    mock_ssh = mock_ssh_class.return_value
    mock_ssh.connect.return_value = True
    
    mock_ssh.execute_command.side_effect = [
        "h1 (192.168.1.10) at AA:BB:CC:DD:EE:FF [ether] on br0", # ARP
        "12345 AA:BB:CC:DD:EE:FF 192.168.1.10 h1 *",             # DHCP
        "link/ether 00:11:22:33:44:55",                         # ip link (router mac)
        "router-host"                                            # hostname
    ]
    
    devices = asus_router.get_device_data()
    assert len(devices) == 2 # Device + Router
    
    # Check device
    device = next(d for d in devices if d['ip'] == "192.168.1.10")
    assert device['mac'] == "AA-BB-CC-DD-EE-FF"
    assert device['hostname'] == "h1"
    
    # Check router
    router = next(d for d in devices if d['ip'] == "192.168.1.1")
    assert router['mac'] == "00-11-22-33-44-55"
    assert router['hostname'] == "router-host"
