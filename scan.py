# scan.py
import os
from routers import get_router  # Import the factory
from dynaconf import Dynaconf

from pathlib import Path

def load_config() -> Dynaconf:
    settings_path = Path('config/settings.toml')
    if not settings_path.exists():
        return Dynaconf()
    return Dynaconf(settings_files=[str(settings_path)])

config = load_config()
def main():
    """Simple test script to fetch and display device data."""

    router = get_router(config)  # Use the factory
    devices = router.get_device_data()

    for device in devices:
        print(device)

if __name__ == "__main__":
    main()
