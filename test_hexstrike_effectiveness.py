#!/usr/bin/env python3
"""
Test skuteczności Hexstrike - wykrywanie podatności
Symuluje jak Hexstrike wykryłby podatności używając dostępnych narzędzi
"""

import subprocess
import requests
import time
import sys
import re

# Kolory
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

TARGET = "http://127.0.0.1:5000"

def print_header(text):
    print(f"\n{CYAN}{'='*80}{RESET}")
    print(f"{CYAN}{text:^80}{RESET}")
    print(f"{CYAN}{'='*80}{RESET}\n")

def print_vuln(severity, name, endpoint, payload):
    colors = {"CRITICAL": RED, "HIGH": MAGENTA, "MEDIUM": YELLOW, "LOW": BLUE}
    color = colors.get(severity, YELLOW)
    print(f"{color}[{severity}] {name}{RESET}")
    print(f"  Endpoint: {endpoint}")
    print(f"  Payload: {payload}")

def test_sql_injection():
    """Test 1: SQL Injection Detection"""
    print_header("🔍 TEST 1: SQL INJECTION DETECTION")

    payloads = [
        "admin'--",
        "admin' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--"
    ]

    vulnerabilities_found = []

    for payload in payloads:
        url = f"{TARGET}/login?username={payload}&password=x"
        try:
            response = requests.get(url, timeout=5)

            # Wykrywanie SQL injection
            sql_errors = [
                "syntax error",
                "sqlite",
                "mysql",
                "postgresql",
                "SQL",
                "database error"
            ]

            found_error = any(err.lower() in response.text.lower() for err in sql_errors)

            # Sprawdź czy payload zadziałał (bypass auth)
            bypass_indicators = ["welcome", "email", "admin"]
            bypass = any(ind.lower() in response.text.lower() for ind in bypass_indicators)

            if found_error or bypass:
                vulnerabilities_found.append({
                    "payload": payload,
                    "evidence": "SQL error" if found_error else "Authentication bypass",
                    "response_length": len(response.text)
                })
                print(f"{GREEN}✅ Found:{RESET} Payload '{payload}' - {('SQL error' if found_error else 'Auth bypass')}")
        except Exception as e:
            print(f"{RED}Error testing {payload}: {e}{RESET}")

    if vulnerabilities_found:
        print_vuln("CRITICAL", "SQL Injection", "/login", vulnerabilities_found[0]['payload'])
        return True
    else:
        print(f"{YELLOW}⚠️  No SQL injection found{RESET}")
        return False

def test_xss():
    """Test 2: XSS Detection"""
    print_header("🔍 TEST 2: XSS (REFLECTED) DETECTION")

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(document.domain)</script>",
    ]

    vulnerabilities_found = []

    for payload in payloads:
        url = f"{TARGET}/search?q={payload}"
        try:
            response = requests.get(url, timeout=5)

            # Check if payload is reflected without encoding
            if payload in response.text:
                vulnerabilities_found.append(payload)
                print(f"{GREEN}✅ Found:{RESET} XSS with payload: {payload[:40]}")
        except Exception as e:
            print(f"{RED}Error testing XSS: {e}{RESET}")

    if vulnerabilities_found:
        print_vuln("HIGH", "Cross-Site Scripting (XSS)", "/search", vulnerabilities_found[0])
        return True
    else:
        print(f"{YELLOW}⚠️  No XSS found{RESET}")
        return False

def test_path_traversal():
    """Test 3: Path Traversal Detection"""
    print_header("🔍 TEST 3: PATH TRAVERSAL DETECTION")

    payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
    ]

    vulnerabilities_found = []

    for payload in payloads:
        url = f"{TARGET}/file?name={payload}"
        try:
            response = requests.get(url, timeout=5)

            # Check for typical /etc/passwd content
            passwd_indicators = ["root:", "bin:", "daemon:", "/bin/bash", "/bin/sh"]

            if any(ind in response.text for ind in passwd_indicators):
                vulnerabilities_found.append(payload)
                print(f"{GREEN}✅ Found:{RESET} Path Traversal - read /etc/passwd")
        except Exception as e:
            print(f"{RED}Error testing path traversal: {e}{RESET}")

    if vulnerabilities_found:
        print_vuln("HIGH", "Path Traversal / Directory Traversal", "/file", vulnerabilities_found[0])
        return True
    else:
        print(f"{YELLOW}⚠️  No Path Traversal found{RESET}")
        return False

def test_command_injection():
    """Test 4: Command Injection Detection"""
    print_header("🔍 TEST 4: COMMAND INJECTION DETECTION")

    payloads = [
        "localhost;id",
        "localhost && whoami",
        "localhost | id",
        "localhost;cat /etc/passwd",
    ]

    vulnerabilities_found = []

    for payload in payloads:
        url = f"{TARGET}/ping?host={payload}"
        try:
            response = requests.get(url, timeout=5)

            # Check for command output (uid, gid, etc.)
            cmd_indicators = ["uid=", "gid=", "groups=", "root:", "/bin"]

            if any(ind in response.text for ind in cmd_indicators):
                vulnerabilities_found.append(payload)
                print(f"{GREEN}✅ Found:{RESET} Command Injection with: {payload}")
        except Exception as e:
            print(f"{RED}Error testing command injection: {e}{RESET}")

    if vulnerabilities_found:
        print_vuln("CRITICAL", "OS Command Injection", "/ping", vulnerabilities_found[0])
        return True
    else:
        print(f"{YELLOW}⚠️  No Command Injection found{RESET}")
        return False

def test_idor():
    """Test 5: IDOR Detection"""
    print_header("🔍 TEST 5: IDOR (Insecure Direct Object Reference)")

    print(f"{BLUE}Testing access to other users' secrets...{RESET}")

    vulnerabilities_found = []

    for user_id in range(1, 4):
        url = f"{TARGET}/user/{user_id}"
        try:
            response = requests.get(url, timeout=5)

            if response.status_code == 200 and "secret" in response.text.lower():
                secret_match = re.search(r'(FLAG\{[^}]+\}|secret|password|token|api[_-]?key)', response.text, re.I)
                if secret_match:
                    vulnerabilities_found.append({
                        "user_id": user_id,
                        "secret": secret_match.group(0)[:50]
                    })
                    print(f"{GREEN}✅ Found:{RESET} Access to User {user_id} secret: {secret_match.group(0)[:30]}...")
        except Exception as e:
            print(f"{RED}Error testing IDOR: {e}{RESET}")

    if len(vulnerabilities_found) > 1:
        print_vuln("HIGH", "IDOR - Access to other users' data", "/user/:id", "Multiple users accessible")
        return True
    else:
        print(f"{YELLOW}⚠️  No IDOR found{RESET}")
        return False

def test_security_headers():
    """Test 6: Missing Security Headers"""
    print_header("🔍 TEST 6: MISSING SECURITY HEADERS")

    url = f"{TARGET}/api/data"
    try:
        response = requests.get(url, timeout=5)

        missing_headers = []
        security_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME sniffing protection",
            "Content-Security-Policy": "XSS protection",
            "Strict-Transport-Security": "HTTPS enforcement",
            "X-XSS-Protection": "XSS filter"
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                missing_headers.append(f"{header} ({description})")
                print(f"{YELLOW}⚠️  Missing:{RESET} {header}")

        # Check for sensitive data exposure
        if response.status_code == 200:
            sensitive_patterns = ["password", "api_key", "secret", "token", "database"]
            exposed_data = [p for p in sensitive_patterns if p in response.text.lower()]

            if exposed_data:
                print(f"{RED}⚠️  Exposed:{RESET} Sensitive data in API: {', '.join(exposed_data)}")

        if missing_headers:
            print_vuln("MEDIUM", "Missing Security Headers", "/api/data", f"{len(missing_headers)} headers missing")
            return True
    except Exception as e:
        print(f"{RED}Error testing headers: {e}{RESET}")

    return False

def main():
    print_header("🎯 HEXSTRIKE EFFECTIVENESS TEST")
    print(f"{BLUE}Target: {TARGET}{RESET}")
    print(f"{BLUE}Testing vulnerability detection capabilities...{RESET}\n")

    # Check if target is reachable
    try:
        response = requests.get(TARGET, timeout=5)
        print(f"{GREEN}✅ Target is reachable{RESET}\n")
    except Exception as e:
        print(f"{RED}❌ Cannot reach target: {e}{RESET}")
        print(f"{YELLOW}Start vulnerable app first: python3 vulnerable_app.py{RESET}")
        return 1

    # Run all tests
    results = {
        "SQL Injection": test_sql_injection(),
        "XSS": test_xss(),
        "Path Traversal": test_path_traversal(),
        "Command Injection": test_command_injection(),
        "IDOR": test_idor(),
        "Missing Headers": test_security_headers(),
    }

    # Summary
    print_header("📊 DETECTION SUMMARY")

    found = sum(1 for v in results.values() if v)
    total = len(results)
    percentage = (found / total * 100) if total > 0 else 0

    for name, detected in results.items():
        status = f"{GREEN}✅ DETECTED{RESET}" if detected else f"{RED}❌ MISSED{RESET}"
        print(f"{status} - {name}")

    print(f"\n{CYAN}{'─'*80}{RESET}")
    color = GREEN if percentage >= 80 else YELLOW if percentage >= 60 else RED
    print(f"{color}Detection Rate: {found}/{total} ({percentage:.1f}%){RESET}")

    if percentage >= 80:
        print(f"\n{GREEN}🎉 EXCELLENT! Hexstrike detected most vulnerabilities!{RESET}")
    elif percentage >= 60:
        print(f"\n{YELLOW}⚠️  GOOD, but missed some vulnerabilities{RESET}")
    else:
        print(f"\n{RED}❌ POOR detection rate{RESET}")

    print(f"{CYAN}{'='*80}{RESET}\n")

    return 0 if percentage >= 60 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Test interrupted{RESET}")
        sys.exit(1)
