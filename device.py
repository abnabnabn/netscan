# device.py
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class Device:
    ip: str
    mac: str  # Primary MAC address (initially discovered)
    name: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    status: str = "offline"
    additional_macs: List[str] = field(default_factory=list)
    additional_ips: List[str] = field(default_factory=list)