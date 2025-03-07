# scan.py
import os
from routers import get_router  # Import the factory
from dynaconf import Dynaconf

config = Dynaconf(
    settings_files=['config/settings.toml']
)
def main():
    """Simple test script to fetch and display device data."""

    router = get_router(config)  # Use the factory
    devices = router.get_device_data()

    for device in devices:
        print(device)

if __name__ == "__main__":
    main()
