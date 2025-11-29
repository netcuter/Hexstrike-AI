"""
Hexstrike 7 PL - Security Utilities
Input validation and sanitization for command execution
"""

import shlex
import re
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Whitelist of allowed security tools (expanded list from tool definitions)
ALLOWED_SECURITY_TOOLS = {
    # Network scanning
    "nmap", "rustscan", "masscan", "autorecon", "arp-scan", "nbtscan",
    # Subdomain enumeration
    "amass", "subfinder", "fierce", "dnsenum", "theharvester",
    # Web scanning
    "gobuster", "dirsearch", "feroxbuster", "ffuf", "dirb", "httpx", "katana",
    "hakrawler", "gau", "waybackurls", "nikto", "whatweb",
    # Vulnerability scanning
    "nuclei", "sqlmap", "wpscan", "arjun", "paramspider", "x8", "jaeles",
    "dalfox", "wafw00f", "testssl", "sslscan", "sslyze",
    # Authentication
    "hydra", "john", "hashcat", "medusa", "patator", "hash-identifier", "hashid",
    # Binary analysis
    "gdb", "radare2", "r2", "ghidra", "binwalk", "ropgadget", "ropper",
    "checksec", "strings", "objdump", "readelf", "xxd", "hexdump",
    # Cloud security
    "prowler", "scout", "trivy", "clair", "kube-hunter", "kube-bench",
    "docker-bench-security", "kubectl", "aws", "az", "gcloud",
    # Forensics
    "volatility", "foremost", "photorec", "testdisk", "steghide",
    "exiftool", "scalpel", "autopsy",
    # OSINT
    "sherlock", "recon-ng", "spiderfoot", "shodan",
    # Enumeration
    "enum4linux", "enum4linux-ng", "smbmap", "rpcclient", "netexec",
    "crackmapexec", "evil-winrm", "responder",
    # Utilities
    "curl", "wget", "nc", "netcat", "socat", "python", "python3",
    "bash", "sh", "perl", "ruby", "php",
    # System tools (needed for functionality)
    "ls", "cat", "grep", "find", "awk", "sed", "sort", "uniq",
    "cut", "tr", "head", "tail", "wc", "file", "which", "whereis",
    "nice", "timeout", "sudo",
}

# Dangerous command patterns that should be blocked even in security context
DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",  # rm -rf /
    r":\(\)\{.*\|.*&\s*\}",  # Fork bomb
    r"mkfs\.",  # Format filesystem
    r"dd\s+if=/dev/zero",  # Wipe disk
    r">\s*/dev/sd[a-z]",  # Write to raw disk
    r"chmod\s+-R\s+777\s+/",  # Dangerous chmod
    r"chown\s+-R.*:\s+/",  # Dangerous chown
]

class SecurityValidator:
    """Validates and sanitizes command inputs for security"""

    def __init__(self):
        self.allowed_tools = ALLOWED_SECURITY_TOOLS
        self.dangerous_patterns = [re.compile(p) for p in DANGEROUS_PATTERNS]

    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate if a command is safe to execute

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern.search(command):
                logger.warning(f"🚨 BLOCKED dangerous command pattern: {command}")
                return False, "Command contains dangerous pattern and was blocked"

        # Extract base command
        try:
            # Parse command safely
            parts = shlex.split(command)
            if not parts:
                return False, "Invalid command format"

            base_command = parts[0].split('/')[-1]  # Get command name without path

            # Check if it's a whitelisted tool
            if base_command not in self.allowed_tools:
                logger.warning(f"⚠️  Command not in whitelist: {base_command}")
                return False, f"Command '{base_command}' is not in allowed tools list"

            return True, None

        except ValueError as e:
            logger.error(f"❌ Failed to parse command: {command} | Error: {e}")
            return False, f"Failed to parse command: {str(e)}"

    def sanitize_parameter(self, param: str) -> str:
        """
        Sanitize a parameter value to prevent injection

        Args:
            param: Parameter value to sanitize

        Returns:
            Sanitized parameter value
        """
        if not param:
            return ""

        # Remove null bytes
        param = param.replace('\x00', '')

        # Remove command separators
        dangerous_chars = [';', '|', '&', '\n', '\r', '`', '$']
        for char in dangerous_chars:
            if char in param:
                logger.warning(f"⚠️  Removed dangerous character '{char}' from parameter")
                param = param.replace(char, '')

        return param

    def build_safe_command(self, tool: str, args: List[str]) -> List[str]:
        """
        Build a safe command array for subprocess without shell=True

        Args:
            tool: Base tool name (e.g., "nmap")
            args: List of arguments

        Returns:
            List of command parts safe for subprocess.Popen
        """
        # Validate tool
        is_valid, error = self.validate_command(tool)
        if not is_valid:
            raise ValueError(f"Invalid tool: {error}")

        # Sanitize all arguments
        safe_args = [self.sanitize_parameter(arg) for arg in args]

        # Return command as list (safe for subprocess without shell=True)
        return [tool] + safe_args

    def parse_command_safely(self, command: str) -> List[str]:
        """
        Parse a command string into a safe list for subprocess

        Args:
            command: Command string to parse

        Returns:
            List of command parts

        Raises:
            ValueError: If command is invalid or dangerous
        """
        # Validate first
        is_valid, error = self.validate_command(command)
        if not is_valid:
            raise ValueError(error)

        try:
            # Use shlex for safe parsing
            parts = shlex.split(command)

            # Sanitize each part
            safe_parts = [self.sanitize_parameter(part) for part in parts]

            return safe_parts

        except ValueError as e:
            raise ValueError(f"Failed to parse command: {str(e)}")


# Global validator instance
_validator = SecurityValidator()


def validate_command(command: str) -> Tuple[bool, Optional[str]]:
    """Global function to validate commands"""
    return _validator.validate_command(command)


def sanitize_parameter(param: str) -> str:
    """Global function to sanitize parameters"""
    return _validator.sanitize_parameter(param)


def parse_command_safely(command: str) -> List[str]:
    """Global function to parse commands safely"""
    return _validator.parse_command_safely(command)


def build_safe_command(tool: str, args: List[str]) -> List[str]:
    """Global function to build safe commands"""
    return _validator.build_safe_command(tool, args)
