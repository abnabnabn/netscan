# routers/__init__.py
from typing import Type

from dynaconf import Dynaconf

from .base import BaseRouter
from .asus import AsusRouter  # Import all concrete implementations

from pathlib import Path

def load_config() -> Dynaconf:
    settings_path = Path('config/settings.toml')
    if not settings_path.exists():
        return Dynaconf()
    return Dynaconf(settings_files=[str(settings_path)])

config = load_config()

def get_router(config: Dynaconf) -> BaseRouter:
    """Router factory: returns an instance of the appropriate router class."""

    router_type = config.general.router_type  # Get router type from general
    
    if router_type == "asus_router":
        return AsusRouter(config.asus_router) # Pass asus_router config
    # Add other router types here:
    # elif router_type == "other_router":
    #     return OtherRouter(config.other_router)
    else:
        raise ValueError(f"Unsupported router type: {router_type}")
