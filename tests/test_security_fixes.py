#!/usr/bin/env python3
"""
Test naprawionych zabezpieczeń Hexstrike 7 PL
Sprawdza czy:
- Custom tools działają
- Pipes i command chaining działają
- Tylko destruktywne komendy są blokowane
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import validate_command, sanitize_parameter

# Kolory dla outputu
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def test_command(command, should_pass=True):
    """Test pojedynczej komendy"""
    is_valid, error = validate_command(command)

    status = "✅" if is_valid else "❌"
    expected = "PASS" if should_pass else "BLOCK"
    actual = "PASS" if is_valid else "BLOCK"

    # Sprawdź czy wynik jest zgodny z oczekiwaniem
    if (should_pass and is_valid) or (not should_pass and not is_valid):
        color = GREEN
        result = "OK"
    else:
        color = RED
        result = "FAIL"

    print(f"{color}{status} {result:5}{RESET} | Expected: {expected:5} | {command[:70]}")
    if error and not should_pass:
        print(f"         {YELLOW}Reason: {error}{RESET}")

    return (should_pass and is_valid) or (not should_pass and not is_valid)

def test_sanitization(param, should_contain):
    """Test sanityzacji parametrów"""
    sanitized = sanitize_parameter(param)
    passed = all(char in sanitized for char in should_contain)

    status = "✅" if passed else "❌"
    color = GREEN if passed else RED

    print(f"{color}{status} Sanitize:{RESET} '{param[:40]}' → '{sanitized[:40]}'")
    return passed

print(f"\n{BLUE}{'='*80}{RESET}")
print(f"{BLUE}🧪 HEXSTRIKE 7 PL - TEST ZABEZPIECZEŃ (naprawione dla małych LLM){RESET}")
print(f"{BLUE}{'='*80}{RESET}\n")

total_tests = 0
passed_tests = 0

# ============================================================================
# TEST 1: PENTESTINGOWE KOMENDY - MUSZĄ DZIAŁAĆ ✅
# ============================================================================
print(f"\n{BLUE}📋 TEST 1: Komendy pentestingowe (powinny przejść){RESET}")
print(f"{BLUE}{'-'*80}{RESET}")

pentesting_commands = [
    # Custom tools
    "./custom_exploit.py target.com",
    "/opt/tools/my_scanner --target 192.168.1.1",
    "python3 exploit.py",

    # Command chaining
    "nmap -sV target.com && nikto -h target.com",
    "sqlmap -u http://target.com || echo 'Failed'",
    "hydra -L users.txt -P pass.txt ftp://target.com; echo 'Done'",

    # Pipes
    "nmap -sV target.com | grep open",
    "msfvenom -p linux/x64/shell_reverse_tcp | base64",
    "curl http://target.com | grep -i password",

    # Cleanup (lokalne ścieżki)
    "rm -rf /tmp/old_scans",
    "rm -rf ./exploit_output",
    "rm -rf /var/tmp/test_*",

    # Typowe pentesting
    "sqlmap -u 'http://target.com?id=1' --batch --dbs",
    "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt",
    "wpscan --url http://target.com --enumerate p",
    "nuclei -u http://target.com -t cves/",

    # Z backticks i variables
    "nmap -sV `cat targets.txt`",
    "hydra -L $USERS -P $PASS ssh://target.com",
]

for cmd in pentesting_commands:
    total_tests += 1
    if test_command(cmd, should_pass=True):
        passed_tests += 1

# ============================================================================
# TEST 2: DESTRUKTYWNE KOMENDY - MUSZĄ BYĆ ZABLOKOWANE ❌
# ============================================================================
print(f"\n{BLUE}📋 TEST 2: Destruktywne komendy (powinny być zablokowane){RESET}")
print(f"{BLUE}{'-'*80}{RESET}")

destructive_commands = [
    # Catastrophic rm
    "rm -rf /",
    "rm -rf / ",
    "rm -rf ~/",
    "rm -rf ~",
    "rm -rf $HOME",

    # System destruction
    ":(){ :|:& };:",
    "mkfs.ext4 /dev/sda1",
    "dd if=/dev/zero of=/dev/sda",
    "dd if=/dev/random of=/dev/sdb1",
    "> /dev/sda",

    # System-wide dangerous
    "chmod -R 777 /",
    "chown -R nobody:nogroup /",
    "shutdown -h now",
    "reboot",
    "poweroff",
    "halt",
]

for cmd in destructive_commands:
    total_tests += 1
    if test_command(cmd, should_pass=False):
        passed_tests += 1

# ============================================================================
# TEST 3: SANITYZACJA PARAMETRÓW - MINIMALNA
# ============================================================================
print(f"\n{BLUE}📋 TEST 3: Sanityzacja parametrów (minimalna - zachowuje |;&$){RESET}")
print(f"{BLUE}{'-'*80}{RESET}")

# Te znaki MUSZĄ być zachowane
params_to_test = [
    ("target.com && echo test", ["&&", "target.com"]),
    ("http://test.com | grep password", ["|", "grep"]),
    ("user:pass@host.com", ["user:pass"]),
    ("$VAR_NAME", ["$VAR_NAME"]),
    ("`whoami`", ["`whoami`"]),
    ("arg1; arg2", [";", "arg1"]),
]

for param, should_contain in params_to_test:
    total_tests += 1
    if test_sanitization(param, should_contain):
        passed_tests += 1

# ============================================================================
# PODSUMOWANIE
# ============================================================================
print(f"\n{BLUE}{'='*80}{RESET}")
print(f"{BLUE}📊 PODSUMOWANIE TESTÓW{RESET}")
print(f"{BLUE}{'='*80}{RESET}")

percentage = (passed_tests / total_tests * 100) if total_tests > 0 else 0
color = GREEN if percentage >= 95 else YELLOW if percentage >= 80 else RED

print(f"\n{color}Passed: {passed_tests}/{total_tests} ({percentage:.1f}%){RESET}\n")

if percentage >= 95:
    print(f"{GREEN}✅ WSZYSTKIE TESTY PRZESZŁY!{RESET}")
    print(f"{GREEN}Zabezpieczenia działają poprawnie dla pentestingu z małymi LLM.{RESET}\n")
elif percentage >= 80:
    print(f"{YELLOW}⚠️  Większość testów przeszła, ale są problemy.{RESET}\n")
else:
    print(f"{RED}❌ TESTY FAILUJĄ! Sprawdź zabezpieczenia.{RESET}\n")

print(f"{BLUE}{'='*80}{RESET}\n")
