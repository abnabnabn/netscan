# routers/asus.py
import re
import logging
from typing import Dict, List, Optional, Callable

from .base import BaseRouter
from utils import format_mac, SSHClient  # Removed _is_apipa
from dynaconf import Dynaconf

logger = logging.getLogger(__name__)

class AsusRouter(BaseRouter):
    """Implementation of BaseRouter for ASUS routers using SSH."""

    def __init__(self, config: Dynaconf):
        self.config = config
        self.router_ip = config.get("router_ip")
        self.router_user = config.get("router_user")
        self.arp_cmd = "arp -a"
        self.dhcp_leases_file = "/var/lib/misc/dnsmasq.leases"
        self.ssh_timeout = config.get("ssh_timeout", 10)

    def get_device_data(self) -> List[Dict]:
        """Retrieves and combines ARP and DHCP data, *including* router info."""
        ssh_client = SSHClient(hostname=self.router_ip, username=self.router_user, timeout=self.ssh_timeout)
        if not ssh_client.connect():
            return []

        arp_output = ssh_client.execute_command(self.arp_cmd)
        dhcp_output = ssh_client.execute_command(f"cat {self.dhcp_leases_file}")
        router_mac = self._get_router_mac(ssh_client)
        router_hostname = self._get_router_hostname(ssh_client)  # Get router hostname
        ssh_client.close()

        arp_devices = self._parse_arp_table(arp_output)
        dhcp_devices = self._parse_dhcp_leases(dhcp_output)

        combined_devices: Dict[str, Dict] = {}
        for device in arp_devices:
            key = f"{device['mac']}:{device['ip']}"
            combined_devices[key] = device
        for device in dhcp_devices:
            key = f"{device['mac']}:{device['ip']}"
            if key in combined_devices:
                if device['hostname']:
                    combined_devices[key]['hostname'] = device['hostname']
            else:
                combined_devices[key] = device

        # Add the router itself as a device
        if router_mac:
            router_device = {
                'ip': self.router_ip,
                'mac': router_mac,
                'hostname': router_hostname
            }
            combined_devices[f"{router_mac}:{self.router_ip}"] = router_device
        else:
            logger.warning("Could not determine router MAC address.")

        return list(combined_devices.values())

    def _parse_lines(self, lines: List[str], parser_func: Callable[[str], Optional[Dict]]) -> List[Dict]:
        """Helper function to parse lines of output."""
        devices: List[Dict] = []
        for line in lines:
            device = parser_func(line)
            if device:
                devices.append(device)
        return devices

    def _parse_arp_line(self, line: str) -> Optional[Dict]:
        """Parses a single line from the ARP table output."""
        arp_pattern = re.compile(r"^(?P<arp_hostname>[^\s\(]+)\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[\w:]+)(?:\s+\[ether\])?(?:\s+on\s+\w+)?\s*$", re.IGNORECASE)
        match = arp_pattern.match(line)
        if not match:
            return None

        ip = match.group('ip')
        mac = format_mac(match.group('mac'))
        arp_hostname = match.group('arp_hostname')

        if mac == "<incomplete>":
            return None

        hostname = None if arp_hostname == "?" else arp_hostname
        if hostname and hostname.lower().endswith("cable.virginm.net"):
            logger.debug(f"Ignoring hostname {hostname} ending in cable.virginm.net")
            return None
        # REMOVED 'apipa' key
        return {"ip": ip, "mac": mac, "hostname": hostname}

    def _parse_arp_table(self, arp_output: str) -> List[Dict]:
        """Parses the ARP table output."""
        return self._parse_lines(arp_output.splitlines(), self._parse_arp_line)

    def _parse_dhcp_line(self, line: str) -> Optional[Dict]:
        """Parses a single line from the DHCP leases output."""
        parts = line.split()
        if len(parts) < 4:
            return None

        _, mac, ip, hostname, *_ = parts + ["*"]
        mac = format_mac(mac)
        hostname = None if hostname == "*" else hostname

        if hostname and hostname.lower().endswith("cable.virginm.net"):
            logger.debug(f"Ignoring hostname {hostname} ending in cable.virginm.net")
            return None
        return {"ip": ip, "mac": mac, "hostname": hostname}

    def _parse_dhcp_leases(self, dhcp_output: str) -> List[Dict]:
        """Parses the DHCP leases output."""
        devices = self._parse_lines(dhcp_output.splitlines(), self._parse_dhcp_line)

        # Handle ISC-style leases
        isc_pattern = re.compile(r"lease\s+(\d+\.\d+\.\d+\.\d+).*?hardware\s+ethernet\s+([\w:]+).*?client-hostname\s+\"([^\"]+)\"", re.DOTALL)
        for ip, mac, hostname in isc_pattern.findall(dhcp_output):
            mac = format_mac(mac)
            if hostname and hostname.lower().endswith("cable.virginm.net"):
                logger.debug(f"Ignoring hostname {hostname} ending in cable.virginm.net")
                continue
            # Use _parse_dhcp_line to ensure consistent handling
            device = self._parse_dhcp_line(f"0 {mac} {ip} {hostname}")
            if device: # Only add if successfully parsed
                devices.append(device)
        return devices

    def _get_router_mac(self, ssh_client: SSHClient) -> Optional[str]:
        """Retrieves the router's MAC address using 'ip link show'."""
        try:
            for interface in ["eth0", "br0", "en0", "wlan0"]:
                output = ssh_client.execute_command(f"ip link show {interface}")
                match = re.search(r"link/ether\s+([\w:]+)", output, re.IGNORECASE)
                if match:
                    return format_mac(match.group(1))
        except Exception as e:
            logger.error(f"Error getting router MAC: {e}")
            return None
        logger.error(f"Could not determine router MAC address.")
        return None

    def _get_router_hostname(self, ssh_client: SSHClient) -> Optional[str]:
        """Retrieves the router's hostname using the 'hostname' command."""
        try:
            return ssh_client.execute_command("hostname").strip()
        except Exception as e:
            logger.error(f"Error getting router hostname: {e}")
            return None
