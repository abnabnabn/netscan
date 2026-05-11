import pytest
from unittest.mock import MagicMock, patch
import os

@pytest.fixture(autouse=True)
def mock_env_and_config():
    """Globally mock environment and configuration to ensure test isolation."""
    # 1. Clear sensitive environment variables
    with patch.dict(os.environ, {}, clear=True):
        # 2. Prevent real SSH connections globally by mocking paramiko.SSHClient
        with patch("paramiko.SSHClient"):
            # 3. Mock Dynaconf globally
            with patch("dynaconf.Dynaconf") as mock_dynaconf:
                mock_instance = mock_dynaconf.return_value
                # Set some safe defaults
                mock_instance.general.json_file = "test_devices.json"
                mock_instance.general.router_type = "asus_router"
                mock_instance.asus_router.router_ip = "127.0.0.1"
                mock_instance.asus_router.router_user = "test_user"
                mock_instance.asus_router.ssh_timeout = 1
                
                # 4. Mock the router factory to prevent real router instantiation
                with patch("routers.get_router") as mock_get_router:
                    mock_get_router.return_value = MagicMock()
                    yield
