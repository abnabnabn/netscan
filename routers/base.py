# routers/base.py
from abc import ABC, abstractmethod
from typing import Dict, List
# No change needed here

class BaseRouter(ABC):
    """Abstract base class for interacting with routers."""

    @abstractmethod
    def get_device_data(self) -> List[Dict]:
        """Retrieves device data from the router.

        Returns:
            A list of dictionaries, each representing a device.  The dictionaries
            should have the following keys: 'ip', 'mac', 'hostname' (optional).
        """
        pass
