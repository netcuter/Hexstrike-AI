#!/usr/bin/env python3
"""
Mini test server dla Hexstrike security validation
Używa tylko security_utils.py - bez Flask dependencies
"""

import json
import subprocess
import sys
from security_utils import validate_command

# Kolory
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{CYAN}{text:^80}{RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")

def execute_validated_command(command):
    """
    Wykonaj komendę z walidacją zabezpieczeń
    Dokładnie tak jak robi to Hexstrike server
    """
    print(f"{BLUE}Command:{RESET} {command}")

    # KROK 1: Walidacja (jak w hexstrike_server.py:9304)
    is_valid, error_msg = validate_command(command)

    if not is_valid:
        print(f"{RED}🚨 BLOCKED:{RESET} {error_msg}")
        return {"status": "blocked", "error": error_msg}

    print(f"{GREEN}✅ VALIDATED:{RESET} Command passed security check")

    # KROK 2: Wykonanie (jak w hexstrike_server.py execute_command)
    try:
        print(f"{YELLOW}▶ Executing...{RESET}")
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print(f"{GREEN}✅ SUCCESS:{RESET} Command executed")
            if result.stdout:
                print(f"{BLUE}Output:{RESET}\n{result.stdout[:200]}")
            return {"status": "success", "stdout": result.stdout, "stderr": result.stderr}
        else:
            print(f"{YELLOW}⚠️  WARNING:{RESET} Exit code {result.returncode}")
            if result.stderr:
                print(f"{RED}Error:{RESET}\n{result.stderr[:200]}")
            return {"status": "error", "returncode": result.returncode, "stderr": result.stderr}

    except subprocess.TimeoutExpired:
        print(f"{RED}⏰ TIMEOUT:{RESET} Command took too long")
        return {"status": "timeout"}
    except Exception as e:
        print(f"{RED}❌ EXCEPTION:{RESET} {str(e)}")
        return {"status": "exception", "error": str(e)}

def test_suite():
    """Test suite - prawdziwe scenariusze pentestingowe"""

    print_header("🧪 HEXSTRIKE 7 PL - REAL WORLD SECURITY TEST")

    tests = [
        {
            "name": "✅ Test 1: Simple file operation",
            "command": "echo 'Hexstrike Test - Done!' > /tmp/hexstrike_test.txt && cat /tmp/hexstrike_test.txt",
            "should_work": True
        },
        {
            "name": "✅ Test 2: Command chaining (pentesting typical)",
            "command": "echo 'Scan started' && echo 'Scan completed' && echo 'Results saved'",
            "should_work": True
        },
        {
            "name": "✅ Test 3: Pipe operations (essential for pentesting)",
            "command": "echo 'vulnerabilities found' | grep -i vuln",
            "should_work": True
        },
        {
            "name": "✅ Test 4: Directory cleanup (pentesting cleanup)",
            "command": "mkdir -p /tmp/hexstrike_scan && echo 'test' > /tmp/hexstrike_scan/results.txt && rm -rf /tmp/hexstrike_scan",
            "should_work": True
        },
        {
            "name": "✅ Test 5: Multiple pipes (log analysis)",
            "command": "echo -e 'line1\\nline2\\nline3' | grep line | wc -l",
            "should_work": True
        },
        {
            "name": "❌ Test 6: Catastrophic filesystem deletion",
            "command": "rm -rf /",
            "should_work": False
        },
        {
            "name": "❌ Test 7: Home directory destruction",
            "command": "rm -rf ~",
            "should_work": False
        },
        {
            "name": "❌ Test 8: Fork bomb",
            "command": ":(){ :|:& };:",
            "should_work": False
        },
        {
            "name": "❌ Test 9: System shutdown",
            "command": "shutdown -h now",
            "should_work": False
        },
        {
            "name": "❌ Test 10: Disk format",
            "command": "mkfs.ext4 /dev/sda1",
            "should_work": False
        },
    ]

    results = []

    for i, test in enumerate(tests, 1):
        print(f"\n{CYAN}{'─'*80}{RESET}")
        print(f"{CYAN}{test['name']}{RESET}")
        print(f"{CYAN}{'─'*80}{RESET}")

        result = execute_validated_command(test['command'])

        # Sprawdź czy wynik jest zgodny z oczekiwaniem
        if test['should_work']:
            success = result['status'] not in ['blocked', 'exception']
        else:
            success = result['status'] == 'blocked'

        results.append({
            "test": test['name'],
            "expected": "ALLOW" if test['should_work'] else "BLOCK",
            "actual": result['status'],
            "success": success
        })

        if success:
            print(f"{GREEN}✅ TEST PASSED{RESET}")
        else:
            print(f"{RED}❌ TEST FAILED{RESET}")

    # Podsumowanie
    print_header("📊 TEST RESULTS SUMMARY")

    passed = sum(1 for r in results if r['success'])
    total = len(results)
    percentage = (passed / total * 100) if total > 0 else 0

    for r in results:
        status = f"{GREEN}✅{RESET}" if r['success'] else f"{RED}❌{RESET}"
        print(f"{status} {r['test']}")

    print(f"\n{CYAN}{'─'*80}{RESET}")
    color = GREEN if percentage >= 90 else YELLOW if percentage >= 70 else RED
    print(f"{color}PASSED: {passed}/{total} ({percentage:.1f}%){RESET}")

    if percentage == 100:
        print(f"\n{GREEN}🎉 PERFECT SCORE! All security tests passed!{RESET}")
        print(f"{GREEN}Hexstrike 7 PL security is working correctly!{RESET}")
    elif percentage >= 90:
        print(f"\n{YELLOW}⚠️  Good score, but some tests failed{RESET}")
    else:
        print(f"\n{RED}❌ Security validation has issues!{RESET}")

    print(f"{CYAN}{'='*80}{RESET}\n")

    return percentage == 100

if __name__ == "__main__":
    try:
        success = test_suite()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Test interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Fatal error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
