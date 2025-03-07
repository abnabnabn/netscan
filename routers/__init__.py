# routers/__init__.py
from typing import Type

from dynaconf import Dynaconf

from .base import BaseRouter
from .asus import AsusRouter  # Import all concrete implementations

config = Dynaconf(
    settings_files=['config/settings.toml']
)

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
