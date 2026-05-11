import pytest
from unittest.mock import patch, MagicMock
from scan import main

@patch("scan.get_router")
def test_scan_main(mock_get_router):
    mock_router = MagicMock()
    mock_get_router.return_value = mock_router
    mock_router.get_device_data.return_value = [{"ip": "1.1.1.1", "mac": "AA-BB"}]
    
    # Capture stdout to avoid printing during tests
    with patch("builtins.print") as mock_print:
        main()
        mock_print.assert_called_with({"ip": "1.1.1.1", "mac": "AA-BB"})
    
    mock_get_router.assert_called_once()
    mock_router.get_device_data.assert_called_once()
