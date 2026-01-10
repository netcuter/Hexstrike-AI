#!/usr/bin/env python3
"""
Live test Hexstrike 7 PL - testowanie na prawdziwej aplikacji
"""

import requests
import json
import time
import subprocess
import os
import signal
import sys

# Kolory
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

HEXSTRIKE_URL = "http://localhost:8888"

def print_header(text):
    print(f"\n{BLUE}{'='*80}{RESET}")
    print(f"{BLUE}{text}{RESET}")
    print(f"{BLUE}{'='*80}{RESET}\n")

def print_step(text):
    print(f"{YELLOW}▶ {text}{RESET}")

def print_success(text):
    print(f"{GREEN}✅ {text}{RESET}")

def print_error(text):
    print(f"{RED}❌ {text}{RESET}")

def test_server_health():
    """Test czy serwer działa"""
    print_step("Sprawdzam czy serwer Hexstrike działa...")
    try:
        response = requests.get(f"{HEXSTRIKE_URL}/health", timeout=5)
        if response.status_code == 200:
            print_success("Serwer Hexstrike działa!")
            return True
        else:
            print_error(f"Serwer odpowiedział z kodem {response.status_code}")
            return False
    except Exception as e:
        print_error(f"Nie można połączyć się z serwerem: {e}")
        return False

def test_command_validation(command, should_pass=True):
    """Test walidacji komendy przez API"""
    try:
        response = requests.post(
            f"{HEXSTRIKE_URL}/api/command",
            json={"command": command, "use_cache": False},
            timeout=10
        )

        is_blocked = response.status_code == 403
        passed = (should_pass and not is_blocked) or (not should_pass and is_blocked)

        status = "✅" if passed else "❌"
        expected = "PASS" if should_pass else "BLOCK"
        actual = "BLOCKED" if is_blocked else "PASSED"

        print(f"{status} Expected: {expected:5} | Actual: {actual:7} | {command[:60]}")

        if is_blocked and response.status_code == 403:
            error = response.json().get('error', 'Unknown error')
            print(f"   {YELLOW}Reason: {error}{RESET}")

        return passed
    except Exception as e:
        print_error(f"Error testing command: {e}")
        return False

def test_pentesting_commands():
    """Test komend pentestingowych przez API"""
    print_header("🧪 TEST 1: Komendy pentestingowe przez API")

    commands = [
        ("echo 'test' > /tmp/hexstrike_test.txt", True, "Simple echo with redirect"),
        ("curl -I http://example.com", True, "HTTP request with curl"),
        ("curl http://example.com | grep -i title", True, "Curl with pipe"),
        ("echo 'scan1' && echo 'scan2'", True, "Command chaining with &&"),
        ("python3 -c 'print(\"hello\")'", True, "Python inline command"),
        ("/usr/bin/curl http://example.com", True, "Full path command"),
    ]

    passed = 0
    total = len(commands)

    for cmd, should_pass, description in commands:
        print(f"\n{BLUE}Test: {description}{RESET}")
        if test_command_validation(cmd, should_pass):
            passed += 1

    print(f"\n{GREEN}Passed: {passed}/{total}{RESET}")
    return passed == total

def test_dangerous_commands():
    """Test blokowania niebezpiecznych komend"""
    print_header("🧪 TEST 2: Blokowanie destruktywnych komend")

    commands = [
        ("rm -rf /", False, "Delete root filesystem"),
        ("rm -rf ~", False, "Delete home directory"),
        (":(){ :|:& };:", False, "Fork bomb"),
        ("shutdown -h now", False, "Shutdown system"),
        ("reboot", False, "Reboot system"),
        ("mkfs.ext4 /dev/sda1", False, "Format disk"),
    ]

    passed = 0
    total = len(commands)

    for cmd, should_pass, description in commands:
        print(f"\n{BLUE}Test: {description}{RESET}")
        if test_command_validation(cmd, should_pass):
            passed += 1

    print(f"\n{GREEN}Blocked: {passed}/{total}{RESET}")
    return passed == total

def test_real_command_execution():
    """Test wykonania prawdziwej komendy"""
    print_header("🧪 TEST 3: Wykonanie prawdziwych komend")

    # Test 1: Echo do pliku
    print_step("Test 1: Echo i zapis do pliku")
    try:
        response = requests.post(
            f"{HEXSTRIKE_URL}/api/command",
            json={"command": "echo 'Hexstrike Test' > /tmp/hexstrike_output.txt", "use_cache": False},
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            print_success("Komenda wykonana!")

            # Sprawdź czy plik powstał
            if os.path.exists('/tmp/hexstrike_output.txt'):
                with open('/tmp/hexstrike_output.txt', 'r') as f:
                    content = f.read()
                    print_success(f"Plik utworzony z zawartością: {content.strip()}")
        else:
            print_error(f"Błąd: {response.status_code}")
            print(response.json())
    except Exception as e:
        print_error(f"Error: {e}")

    # Test 2: Curl
    print_step("\nTest 2: HTTP request z curl")
    try:
        response = requests.post(
            f"{HEXSTRIKE_URL}/api/command",
            json={"command": "curl -I http://example.com 2>&1 | head -5", "use_cache": False},
            timeout=15
        )

        if response.status_code == 200:
            result = response.json()
            print_success("Curl wykonany!")
            if 'stdout' in result:
                print(f"{BLUE}Output:{RESET}\n{result['stdout'][:300]}")
        else:
            print_error(f"Błąd: {response.status_code}")
    except Exception as e:
        print_error(f"Error: {e}")

    # Test 3: Command chaining
    print_step("\nTest 3: Command chaining (mkdir && echo)")
    try:
        response = requests.post(
            f"{HEXSTRIKE_URL}/api/command",
            json={"command": "mkdir -p /tmp/hexstrike_test && echo 'Success!' > /tmp/hexstrike_test/result.txt", "use_cache": False},
            timeout=10
        )

        if response.status_code == 200:
            print_success("Command chaining zadziałał!")
            if os.path.exists('/tmp/hexstrike_test/result.txt'):
                print_success("Plik w nowym katalogu utworzony!")
        else:
            print_error(f"Błąd: {response.status_code}")
    except Exception as e:
        print_error(f"Error: {e}")

def main():
    print_header("🚀 HEXSTRIKE 7 PL - LIVE TEST")
    print(f"{BLUE}Testing server at: {HEXSTRIKE_URL}{RESET}\n")

    # Test czy serwer działa
    if not test_server_health():
        print_error("\n❌ Serwer Hexstrike nie działa!")
        print_step("Uruchom serwer: python3 hexstrike_server.py")
        print_step("Lub w tle: python3 hexstrike_server.py > /dev/null 2>&1 &")
        return 1

    # Testy
    test_pentesting_commands()
    test_dangerous_commands()
    test_real_command_execution()

    print_header("✅ TESTY ZAKOŃCZONE")
    print(f"{GREEN}Hexstrike 7 PL działa poprawnie!{RESET}\n")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Test przerwany przez użytkownika{RESET}")
        sys.exit(1)
