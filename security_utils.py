"""
Hexstrike 7 PL - Security Utilities
Input validation and sanitization for command execution
"""

import shlex
import re
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# REMOVED: Whitelist approach - too restrictive for pentesting tool
# Allow all tools including custom exploits, scripts, and new security tools
# Only block explicitly dangerous patterns below

# Dangerous command patterns - block only truly destructive operations
# Designed for small LLM models (1.5B-7B) that might hallucinate dangerous commands
DANGEROUS_PATTERNS = [
    # Catastrophic filesystem destruction
    r"rm\s+-rf\s+/$",                          # rm -rf / (root only)
    r"rm\s+-rf\s+/\s",                         # rm -rf / (with space)
    r"rm\s+-rf\s+~/?$",                        # rm -rf ~ or rm -rf ~/
    r"rm\s+-rf\s+\$HOME",                      # rm -rf $HOME

    # System destruction
    r":\(\)\{.*\|.*&\s*\}",                    # Fork bomb
    r"mkfs\.",                                  # Format filesystem
    r"dd\s+if=/dev/(zero|random)\s+of=/dev/sd", # Wipe disk
    r">\s*/dev/sd[a-z]",                       # Write to raw disk

    # System-wide dangerous operations
    r"chmod\s+-R\s+777\s+/$",                  # chmod 777 on root only
    r"chown\s+-R.*\s+/$",                      # chown on root only
    r"(shutdown|reboot|poweroff|halt)(\s|$)",  # System shutdown/reboot (with or without args)

    # NOTE: These patterns allow:
    # - rm -rf /tmp/*, /var/tmp/*, ./local/paths (OK for pentesting cleanup)
    # - Command chaining: &&, ||, ; (essential for pentesting)
    # - Pipes: | (essential for pentesting)
    # - Custom tools: ./exploit.py, /opt/custom/tool (no whitelist)
]

class SecurityValidator:
    """Validates command inputs for security - blocks only truly dangerous operations"""

    def __init__(self):
        self.dangerous_patterns = [re.compile(p) for p in DANGEROUS_PATTERNS]

    def validate_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Validate if a command is safe to execute
        Only blocks truly dangerous operations - allows custom tools, pipes, chaining

        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        if not command or not command.strip():
            return False, "Empty command"

        # Check for dangerous patterns only
        for pattern in self.dangerous_patterns:
            if pattern.search(command):
                logger.warning(f"🚨 BLOCKED dangerous command pattern: {command}")
                return False, "Command contains dangerous pattern and was blocked"

        # Allow everything else (no whitelist)
        # This includes:
        # - Custom tools: ./exploit.py, /opt/tools/scanner
        # - Command chaining: nmap && nikto
        # - Pipes: msfvenom | base64
        # - All pentesting operations
        return True, None

    def sanitize_parameter(self, param: str) -> str:
        """
        Sanitize a parameter value to prevent injection
        MINIMAL sanitization - only removes truly dangerous characters
        Allows |, ;, &, $ which are needed for pentesting commands

        Args:
            param: Parameter value to sanitize

        Returns:
            Sanitized parameter value
        """
        if not param:
            return ""

        # Remove only null bytes and newlines (command separators in different context)
        # ALLOW: |, ;, &, $, ` for pentesting use (pipes, chaining, variables, backticks)
        dangerous_chars = ['\x00', '\n', '\r']
        for char in dangerous_chars:
            if char in param:
                logger.warning(f"⚠️  Removed dangerous character (null/newline) from parameter")
                param = param.replace(char, '')

        return param

    def build_safe_command(self, tool: str, args: List[str]) -> List[str]:
        """
        Build a safe command array for subprocess without shell=True
        No whitelist - allows custom tools

        Args:
            tool: Base tool name (e.g., "nmap", "./exploit.py")
            args: List of arguments

        Returns:
            List of command parts safe for subprocess.Popen
        """
        # Validate tool (only checks dangerous patterns, no whitelist)
        is_valid, error = self.validate_command(tool)
        if not is_valid:
            raise ValueError(f"Invalid tool: {error}")

        # Minimal sanitization (only null bytes and newlines)
        safe_args = [self.sanitize_parameter(arg) for arg in args]

        # Return command as list (safe for subprocess without shell=True)
        return [tool] + safe_args

    def parse_command_safely(self, command: str) -> List[str]:
        """
        Parse a command string into a safe list for subprocess
        Allows pipes, chaining, custom tools - minimal validation

        Args:
            command: Command string to parse

        Returns:
            List of command parts

        Raises:
            ValueError: If command is invalid or dangerous
        """
        # Validate first (only checks dangerous patterns)
        is_valid, error = self.validate_command(command)
        if not is_valid:
            raise ValueError(error)

        try:
            # Use shlex for safe parsing
            parts = shlex.split(command)

            # Minimal sanitization (only null bytes and newlines)
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
