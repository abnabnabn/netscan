# utils.py
import re
import paramiko
import logging
import getpass
from typing import Optional

logger = logging.getLogger(__name__)

def format_mac(mac: str) -> str:
    """Formats a MAC address to lowercase with colons."""
    return mac.lower().replace("-", ":")

def is_valid_ipv4(ip: str) -> bool:
    """Checks if a string is a valid IPv4 address."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

class SSHClient:
    """A utility class for handling SSH connections and command execution."""

    def __init__(self, hostname: str, username: str, password: Optional[str] = None,
                  timeout: int = 10):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None

    def connect(self) -> bool:
        """Connects to the SSH server, using default SSH keys and agent."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.password:
                # Use password if provided
                self.client.connect(hostname=self.hostname, username=self.username,
                                        password=self.password, timeout=self.timeout)
            else:
                # Attempt automatic key-based authentication (look_for_keys=True, allow_agent=True)
                try:
                    self.client.connect(hostname=self.hostname, username=self.username,
                                            timeout=self.timeout, look_for_keys=True, allow_agent=True)
                except paramiko.ssh_exception.PasswordRequiredException:
                    password = getpass.getpass(f"Enter password for {self.username}@{self.hostname}: ")
                    self.client.connect(hostname=self.hostname, username=self.username,
                                        password=password, timeout=self.timeout)

            return True
        except Exception as e:
            logger.error(f"Error connecting to {self.hostname}: {e}")
            return False

    def execute_command(self, command: str) -> str:
        """Executes a command on the connected SSH server."""
        if not self.client:
            raise Exception("SSH client not connected. Call connect() first.")
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            error = stderr.read().decode().strip()
            output = stdout.read().decode() #type: ignore
            if error:
                logger.warning(f"Command '{command}' returned error: {error}")
            return output
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return ""

    def close(self):
        """Closes the SSH connection."""
        if self.client:
            self.client.close()
            self.client = None
