# network_scanner.py
import argparse
import logging
from typing import Dict, List, Tuple, Optional, Callable
from pathlib import Path
from datetime import datetime
import ipaddress
import json

from device import Device
from routers import get_router
from data import load_device_data, save_device_data
from utils import format_mac, is_valid_ipv4, SSHClient
from dynaconf import Dynaconf
from mac_vendor_lookup import MacLookup

# Load settings
config = Dynaconf(
    settings_files=['config/settings.toml'],
)

logger = logging.getLogger(__name__)

def add_new_device(current_devices: Dict[str, Dict], hostname: str | None, mac: str, ip: str):
    """Adds a new device to the current_devices dictionary."""
    key = f"{mac}:{ip}"
    current_devices[key] = {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "multiple_mac": False,
        "multiple_ip": False,
        "processed": False,
    }
    logger.debug(f"Added new device: {key} - {hostname or ''}")

def update_device(current_devices: Dict[str, Dict], hostname: str | None, mac: str, ip: str):
    """Updates the hostname of an existing device in current_devices."""
    key = f"{mac}:{ip}"
    if key in current_devices:
        if hostname:
            current_devices[key]["hostname"] = hostname
        logger.debug(f"Updated device: {key} - Hostname: {hostname or ''}")
    else:
        logger.warning(f"Attempted to update non-existent device: {key}")

def detect_multiple_mac_ip(current_devices: Dict[str, Dict]):
    """Detects and flags multiple MACs/IPs within current_devices."""
    mac_counts: Dict[str, int] = {}
    ip_counts: Dict[str, int] = {}

    for device in current_devices.values():
        mac = device['mac']
        ip = device['ip']
        mac_counts[mac] = mac_counts.get(mac, 0) + 1
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for device in current_devices.values():
        #Prioritise multiple MAC addresses
        device['multiple_mac'] = mac_counts.get(device['mac'], 0) > 1
        device['multiple_ip'] = (ip_counts.get(device['ip'], 0) > 1) and (not device['multiple_mac'])

def _match_existing_device(current_device: Dict, existing_device: Dict, current_devices: Dict[str, Dict]) -> bool:
    """Helper function to check if a current device matches an existing device.

    Args:
        current_device: The device data from the current scan.
        existing_device: A device entry from the existing json_list.
        current_devices: Dictionary of current devices, for hostname uniqueness.

    Returns:
        True if the devices match according to the specified criteria,
        False otherwise.
    """

    # Hostname must be valid and unique within the *current* scan.
    if not (current_device.get('hostname')):
        return False
    hostname_count = sum(1 for dev in current_devices.values()
                            if dev.get('hostname') == current_device['hostname'])

    if hostname_count != 1:
        return False # Hostname is not unique in current scan

    return (existing_device.get('hostname') == current_device['hostname'] and
            existing_device.get('vendor') == get_vendor_from_mac(current_device['mac']))


def find_matching_device(current_device: Dict, json_list: List[Dict], json_dict: Dict[str, Dict], current_devices: Dict[str, Dict]) -> Optional[Dict]:
    """Finds a matching device in json_list based on current_device."""
    current_ip = current_device['ip']
    current_mac = current_device['mac']
    current_hostname = current_device.get('hostname')

    # 1. IP *and* MAC Match:
    if current_ip in json_dict:
        existing_device = json_dict[current_ip]
        if existing_device['mac'] == current_mac:
            return existing_device  # Highest confidence

        # 2. IP Match *Only* (Hostname *and* Vendor must also match):
        if _match_existing_device(current_device, existing_device, current_devices):
            return existing_device  # IP, Hostname, and Vendor match

     # 3. only MAC match
    for existing_device in json_list:
        if  existing_device.get('mac') == current_device['mac']:
            return existing_device

    # 4. Hostname and Vendor Match (for new IPs, prioritize offline):
    if current_hostname:
        for existing_device in json_list:  # Search ALL devices (online + offline)
            if _match_existing_device(current_device, existing_device, current_devices):
                return existing_device  # Hostname and Vendor match

    # 5. No Match:
    return None

def _update_existing_devices(current_devices: Dict[str, Dict], json_dict: Dict[str, Dict], json_list: List[Dict]) -> bool:
    """Updates existing device entries in json_list based on current_devices."""
    updated = False
    for key, current_device in current_devices.items():
        #ip_address = current_device['ip']  # Use the IP as the key - NO: Use find_matching_device
        matched_device = find_matching_device(current_device, json_list, json_dict, current_devices)
        if matched_device:
            # We matched by IP address in find_matching_device
            if matched_device['ip'] == current_device['ip']:
                if current_device.get('hostname') and matched_device.get('hostname') != current_device.get('hostname'):
                    matched_device['hostname'] = current_device.get('hostname')
                    updated = True
                matched_device['status'] = "online"
                # Handle MAC address changes *for this IP*.
                if matched_device['mac'] != current_device['mac']:
                    # Add the *old* MAC to additional_macs (if not already there)
                    if matched_device['mac'] not in matched_device.setdefault('additional_macs', []):
                        matched_device['additional_macs'].append(matched_device['mac'])
                        updated = True
                    # Update the *primary* MAC address.
                    matched_device['mac'] = current_device['mac']
                    updated = True
                    logger.info(f"Device MAC changed for IP { matched_device['ip'] }: Old MAC: {matched_device['mac']}, New MAC: {current_device['mac']}")

            #we matched by hostname or mac, so update
            else:
                matched_device['ip'] = current_device['ip']
                matched_device['mac'] = current_device['mac']
                if current_device.get('hostname'):
                    matched_device['hostname'] = current_device.get('hostname')
                matched_device['status'] = "online"
                updated = True
            current_device['processed'] = True  # Mark as processed in *current* devices
    return updated

def _add_new_devices(current_devices: Dict[str, Dict], json_list: List[Dict]) -> bool:
    """Adds new devices (IP not found), tries hostname/MAC match first."""
    updated = False
    for current_device in current_devices.values():
        if not current_device.get('processed'):
            ip = current_device['ip']
            mac = current_device['mac']
            hostname = current_device.get('hostname')

            if not current_device.get('multiple_ip'):
                new_device = {
                    'ip': ip,
                    'mac': mac,
                    'name': None,
                    'hostname': hostname,
                    'vendor': None,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': None,
                    'status': "online",
                    'additional_macs': [],
                    'additional_ips': [],
                }
                json_list.append(new_device)
                logger.info(f"New device added: {new_device}")
                updated = True

            current_device['processed'] = True  # Mark as processed
    return updated

def _mark_offline_devices(current_devices: Dict[str, Dict], json_list: List[Dict]) -> bool:
    """Marks devices as offline if their IP is not in current_devices."""
    updated = False
    current_ips = {d['ip'] for d in current_devices.values()}
    for device in json_list:
        if device.get('ip') not in current_ips and device.get('status') == 'online':
            device['status'] = 'offline'
            updated = True
            logger.info(f"Device went offline: IP={device.get('ip')}, MAC={device.get('mac')}")
    return updated

def _populate_additional_macs_ips(current_devices: Dict[str, Dict], json_list: List[Dict])-> bool:
    """Populates the additional_macs and additional_ips fields based on *current* scan."""
    updated = False

    # Create dictionaries keyed by IP and MAC for efficient lookup within current_devices
    ip_to_devices = {}
    mac_to_devices = {}
    for key, device_data in current_devices.items():
        ip = device_data['ip']
        mac = device_data['mac']
        ip_to_devices.setdefault(ip, []).append(device_data)
        mac_to_devices.setdefault(mac, []).append(device_data)

    # Build a dictionary of IP -> json file entry
    ip_to_json= {device.get('ip'): device for device in json_list if device.get('ip') and device.get('status') == 'online'}

    for ip, json_device in ip_to_json.items():
      #Add additional MACs
      if ip in ip_to_devices: # Should always be true
        for current_device in ip_to_devices[ip]:
          if current_device['mac'] != json_device['mac'] and current_device['mac'] not in json_device.setdefault('additional_macs',[]):
            json_device.setdefault('additional_macs', []).append(current_device['mac'])
            updated = True

    for mac, current_devices in mac_to_devices.items():
      #get all the json entries with this mac
      relevant_json_devices = [d for d in json_list if d['mac'] == mac and d['status'] == "online"] #find online devices in json
      for json_device in relevant_json_devices:  #for each of those
        for current_device in current_devices:  #check against the current devices
            if current_device['ip'] != json_device['ip'] and current_device['ip'] not in json_device.setdefault('additional_ips',[]):
              json_device.setdefault('additional_ips',[]).append(current_device['ip'])
              updated = True
    return updated

def update_device_data(current_devices: Dict[str, Dict], json_list: List[Dict], original_json_list: List[Dict]) -> Tuple[List[Dict], bool]:
    """Updates json_list based on current_devices; handles new/changed IPs/MACs."""

    # Key JSON dict by IP *only*.
    json_dict = {device.get('ip'): device for device in json_list if device.get('ip')}

    updated = False
    updated = _update_existing_devices(current_devices, json_dict, json_list) or updated
    updated = _add_new_devices(current_devices, json_list) or updated
    updated = _mark_offline_devices(current_devices, json_list) or updated
    updated = _populate_additional_macs_ips(current_devices, json_list) or updated

    return json_list, updated

def populate_vendor_and_name(json_list: List[Dict], mac_lookup: MacLookup):
    """Populates the 'vendor' and 'name' fields in the device list."""
    for device in json_list:
        try:
            device['vendor'] = mac_lookup.lookup(device['mac'])
        except Exception as e:
            logger.debug(f"Could not determine vendor for MAC {device.get('mac')}: {e}") # Changed to debug
            device['vendor'] = None

        if not device.get('name'):
            device['name'] = device.get('hostname') or device.get('vendor') or "Unknown Device"

def validate_scan_results(current_devices_list: List[Dict], json_list: List[Dict]):
    """Validates that all devices from the router are present in the json_list."""
    missing_devices = []
    current_ips = {d['ip'] for d in current_devices_list}
    json_ips = {d['ip'] for d in json_list if d.get('status') == 'online'}

    for ip in current_ips:
        if ip not in json_ips:
            # Find the corresponding device in current_devices for more info
            for device in current_devices_list:
                if device['ip'] == ip:
                    missing_devices.append(device)
                    break

    if missing_devices:
        logger.error("Validation Error: The following devices from the router are missing from the scan results:")
        for device in missing_devices:
            logger.error(f"  - IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device.get('hostname', 'N/A')}")
        # Optionally, raise an exception here
        # raise ValueError("Scan results validation failed.")
    else:
        logger.info("Validation successful: All router-reported devices are present in the scan results.")

def _prepare_for_comparison(json_list: List[Dict]) -> str:
    """Prepares the JSON data for comparison by removing last_seen and sorting."""
    # Create a deep copy to avoid modifying the original list
    comparable_list = [device.copy() for device in json_list]
    for device in comparable_list:
        device.pop('last_seen', None)  # Remove last_seen, None prevents KeyError
    return json.dumps(comparable_list, sort_keys=True)

def get_vendor_from_mac(mac_address):
    return MacLookup().lookup(mac_address)

def run_scan(update_mac_db: bool = False):
    """Main function to perform the network scan."""
    logger.info("Starting network scan")

    # --- Router Interaction ---
    router = get_router(config)
    current_devices_list = router.get_device_data()
    current_devices = {f"{d['mac']}:{d['ip']}": d for d in current_devices_list}

    # --- Detect multiple MACs/IPs ---
    detect_multiple_mac_ip(current_devices)

    # --- Data Loading and Processing ---
    json_file_path = Path(config.general.get("json_file"))
    json_list = load_device_data(json_file_path)
    original_json_list = load_device_data(json_file_path) #load in original file

    # --- Pre-process json_list ---
    for device in json_list:
        device['additional_macs'] = []
        device['additional_ips'] = []
        device['last_seen'] = ""
        device['status'] = "offline"

    # --- Update device data ---
    updated_json_list, _ = update_device_data(current_devices, json_list, original_json_list) # We don't need the flag

    # --- Populate Vendor and Name ---
    mac_lookup = MacLookup()  # Create instance: automatic updates happen here
    populate_vendor_and_name(updated_json_list, mac_lookup)

    # --- Sort by IP Address ---
    updated_json_list.sort(key=lambda d: ipaddress.IPv4Address(d['ip']))

    # --- Validation Check ---
    validate_scan_results(current_devices_list, updated_json_list)

    # --- Prepare for comparison (remove last_seen and sort)---
    original_json_str = _prepare_for_comparison(original_json_list)
    updated_json_str = _prepare_for_comparison(updated_json_list)

    # --- Update last_seen for online devices, AFTER comparison ---
    current_time = datetime.now().isoformat()
    for device in updated_json_list:
        if device['status'] == "online":
            device['last_seen'] = current_time

    # --- Save if needed (compare JSON strings) ---
    if updated_json_str != original_json_str:
        save_device_data(updated_json_list, json_file_path)
        logger.info(f"Updated device database saved to {config.general.get('json_file')}")
    else:
        logger.info("No changes detected.")

def main():
    parser = argparse.ArgumentParser(description="Network device scanner")
    parser.add_argument("--update-mac-db", action="store_true", help="Force update of the MAC vendor database")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if args.update_mac_db:
        # Update the database if requested.
        MacLookup().update_vendors()

    run_scan()

if __name__ == "__main__":
    main()
