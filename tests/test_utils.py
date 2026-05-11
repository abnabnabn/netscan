import pytest
from unittest.mock import MagicMock, patch
from utils import format_mac, is_valid_ipv4, SSHClient
import paramiko

def test_format_mac():
    assert format_mac("aa:bb:cc:dd:ee:ff") == "AA-BB-CC-DD-EE-FF"
    assert format_mac("AA:BB:CC:DD:EE:FF") == "AA-BB-CC-DD-EE-FF"
    assert format_mac("aa-bb-cc-dd-ee-ff") == "AA-BB-CC-DD-EE-FF"
    assert format_mac("aabbccddeeff") == "AABBCCDDEEFF"

def test_is_valid_ipv4():
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("0.0.0.0") is True
    assert is_valid_ipv4("255.255.255.255") is True
    assert is_valid_ipv4("256.256.256.256") is False
    assert is_valid_ipv4("192.168.1") is False
    assert is_valid_ipv4("192.168.1.1.1") is False
    assert is_valid_ipv4("abc.def.ghi.jkl") is False
    assert is_valid_ipv4("192.168.1.a") is False

@patch("paramiko.SSHClient")
def test_ssh_client_connect_success(mock_ssh):
    mock_instance = mock_ssh.return_value
    client = SSHClient("host", "user", "pass")
    assert client.connect() is True
    mock_instance.connect.assert_called_with(
        hostname="host", username="user", password="pass", timeout=10
    )

@patch("paramiko.SSHClient")
def test_ssh_client_connect_failure(mock_ssh):
    mock_instance = mock_ssh.return_value
    mock_instance.connect.side_effect = Exception("Connection failed")
    client = SSHClient("host", "user", "pass")
    assert client.connect() is False

@patch("paramiko.SSHClient")
def test_ssh_client_execute_command_success(mock_ssh):
    mock_instance = mock_ssh.return_value
    client = SSHClient("host", "user", "pass")
    client.connect()
    
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b"output"
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_instance.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)
    
    assert client.execute_command("ls") == "output"

@patch("paramiko.SSHClient")
def test_ssh_client_execute_command_warning(mock_ssh):
    mock_instance = mock_ssh.return_value
    client = SSHClient("host", "user", "pass")
    client.connect()
    
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b"output"
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b"some error"
    mock_instance.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)
    
    # Should still return output but log a warning
    assert client.execute_command("ls") == "output"

@patch("paramiko.SSHClient")
def test_ssh_client_execute_command_exception(mock_ssh):
    mock_instance = mock_ssh.return_value
    client = SSHClient("host", "user", "pass")
    client.connect()
    mock_instance.exec_command.side_effect = Exception("Exec failed")
    
    assert client.execute_command("ls") == ""

@patch("paramiko.SSHClient")
def test_ssh_client_execute_command_no_client(mock_ssh):
    client = SSHClient("host", "user", "pass")
    with pytest.raises(Exception, match="SSH client not connected"):
        client.execute_command("ls")

@patch("paramiko.SSHClient")
def test_ssh_client_close(mock_ssh):
    mock_instance = mock_ssh.return_value
    client = SSHClient("host", "user", "pass")
    client.connect()
    client.close()
    mock_instance.close.assert_called_once()
    assert client.client is None

@patch("paramiko.SSHClient")
@patch("getpass.getpass")
def test_ssh_client_connect_password_prompt(mock_getpass, mock_ssh):
    mock_instance = mock_ssh.return_value
    # First call to connect raises PasswordRequiredException, second call succeeds
    mock_instance.connect.side_effect = [
        paramiko.ssh_exception.PasswordRequiredException(),
        None
    ]
    mock_getpass.return_value = "secret"
    
    client = SSHClient("host", "user") # No password provided
    assert client.connect() is True
    mock_getpass.assert_called_once()
