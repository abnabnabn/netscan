import pytest
from unittest.mock import MagicMock
from routers import get_router
from routers.asus import AsusRouter

def test_get_router_asus():
    config = MagicMock()
    config.general.router_type = "asus_router"
    config.asus_router = {"some": "config"}
    
    router = get_router(config)
    assert isinstance(router, AsusRouter)

def test_get_router_unsupported():
    config = MagicMock()
    config.general.router_type = "unknown"
    
    with pytest.raises(ValueError, match="Unsupported router type"):
        get_router(config)
