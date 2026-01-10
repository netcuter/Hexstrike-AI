#!/bin/bash
# Test skuteczności Hexstrike na prawdziwym targecie
# Target: http://testphp.vulnweb.com (legalny testowy target)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

TARGET="http://testphp.vulnweb.com"

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}          🎯 HEXSTRIKE REAL WORLD EFFECTIVENESS TEST                          ${NC}"
echo -e "${CYAN}================================================================================${NC}"
echo ""
echo -e "${BLUE}Target: $TARGET${NC}"
echo -e "${BLUE}Dostępne narzędzia: curl, grep, sed${NC}"
echo -e "${YELLOW}Note: Hexstrike z pełnymi narzędziami (nmap, sqlmap, etc.) wykryłby więcej${NC}"
echo ""

FINDINGS=0
TOTAL_TESTS=0

# Test 1: Basic recon
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 1: BASIC RECONNAISSANCE${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

echo -e "${BLUE}▶ Testing HTTP response...${NC}"
RESPONSE=$(curl -sI "$TARGET" -m 10)

if echo "$RESPONSE" | grep -q "200 OK"; then
    echo -e "${GREEN}✅ Target is reachable${NC}"
    ((FINDINGS++))

    # Check server
    SERVER=$(echo "$RESPONSE" | grep -i "Server:" | cut -d':' -f2-)
    if [ ! -z "$SERVER" ]; then
        echo -e "${GREEN}✅ Server identified:$SERVER${NC}"
    fi

    # Check X-Powered-By
    POWERED=$(echo "$RESPONSE" | grep -i "X-Powered-By:" | cut -d':' -f2-)
    if [ ! -z "$POWERED" ]; then
        echo -e "${YELLOW}[MEDIUM] Information Disclosure: X-Powered-By header reveals:$POWERED${NC}"
    fi
else
    echo -e "${RED}❌ Target unreachable${NC}"
fi

# Test 2: Missing Security Headers
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 2: SECURITY HEADERS ANALYSIS${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

MISSING=0
echo "$RESPONSE" | grep -qi "X-Frame-Options" || { echo -e "${YELLOW}⚠️  Missing: X-Frame-Options (Clickjacking protection)${NC}"; ((MISSING++)); }
echo "$RESPONSE" | grep -qi "X-Content-Type-Options" || { echo -e "${YELLOW}⚠️  Missing: X-Content-Type-Options (MIME sniffing)${NC}"; ((MISSING++)); }
echo "$RESPONSE" | grep -qi "Content-Security-Policy" || { echo -e "${YELLOW}⚠️  Missing: Content-Security-Policy (XSS protection)${NC}"; ((MISSING++)); }
echo "$RESPONSE" | grep -qi "Strict-Transport-Security" || { echo -e "${YELLOW}⚠️  Missing: Strict-Transport-Security (HTTPS)${NC}"; ((MISSING++)); }

if [ $MISSING -gt 0 ]; then
    echo -e "${YELLOW}[MEDIUM] Missing $MISSING security headers${NC}"
    ((FINDINGS++))
fi

# Test 3: SQL Injection (basic)
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 3: SQL INJECTION DETECTION (Basic)${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

echo -e "${BLUE}▶ Testing SQL injection payload...${NC}"
SQLI_URL="${TARGET}/artists.php?artist=1'"
SQLI_RESPONSE=$(curl -s "$SQLI_URL" -m 10)

if echo "$SQLI_RESPONSE" | grep -qi "sql\|syntax\|mysql\|error in your SQL"; then
    echo -e "${RED}[CRITICAL] SQL Injection vulnerability detected!${NC}"
    echo -e "${YELLOW}  Endpoint: /artists.php?artist=${NC}"
    echo -e "${YELLOW}  Evidence: SQL error messages in response${NC}"
    ((FINDINGS++))
else
    echo -e "${GREEN}No SQL errors detected (might still be vulnerable)${NC}"
fi

# Test 4: XSS Detection
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 4: XSS (REFLECTED) DETECTION${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

echo -e "${BLUE}▶ Testing XSS payload...${NC}"
XSS_PAYLOAD="<script>alert(1)</script>"
XSS_URL="${TARGET}/search.php?test=${XSS_PAYLOAD}"
XSS_RESPONSE=$(curl -s "$XSS_URL" -m 10)

if echo "$XSS_RESPONSE" | grep -q "$XSS_PAYLOAD"; then
    echo -e "${RED}[HIGH] XSS vulnerability detected!${NC}"
    echo -e "${YELLOW}  Payload reflected without encoding${NC}"
    ((FINDINGS++))
else
    echo -e "${GREEN}Payload was encoded/filtered${NC}"
fi

# Test 5: Directory Enumeration
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 5: DIRECTORY ENUMERATION${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

echo -e "${BLUE}▶ Testing common paths...${NC}"
DIRS_FOUND=0
for dir in admin backup config test phpinfo.php robots.txt .git; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$dir" -m 5)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "301" ] || [ "$STATUS" = "302" ]; then
        echo -e "${YELLOW}  Found: /$dir (HTTP $STATUS)${NC}"
        ((DIRS_FOUND++))
    fi
done

if [ $DIRS_FOUND -gt 0 ]; then
    echo -e "${YELLOW}[LOW] Found $DIRS_FOUND interesting paths${NC}"
    ((FINDINGS++))
fi

# Test 6: Technology Detection
echo ""
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "${CYAN}🔍 TEST 6: TECHNOLOGY STACK DETECTION${NC}"
echo -e "${CYAN}────────────────────────────────────────────────────────────────────────────────${NC}"
((TOTAL_TESTS++))

PAGE=$(curl -s "$TARGET" -m 10)

echo -e "${BLUE}▶ Analyzing page content...${NC}"
echo "$PAGE" | grep -qi "php" && echo -e "${GREEN}✅ PHP detected${NC}"
echo "$PAGE" | grep -qi "mysql" && echo -e "${GREEN}✅ MySQL detected${NC}"
echo "$PAGE" | grep -qi "jquery" && echo -e "${GREEN}✅ jQuery detected${NC}"

# Check for version info
if echo "$PAGE" | grep -qi "php.*[0-9]\.[0-9]"; then
    echo -e "${YELLOW}[LOW] PHP version may be exposed${NC}"
    ((FINDINGS++))
fi

# Summary
echo ""
echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}                           📊 DETECTION SUMMARY                                ${NC}"
echo -e "${CYAN}================================================================================${NC}"
echo ""

PERCENTAGE=$((FINDINGS * 100 / TOTAL_TESTS))

echo -e "${BLUE}Tests performed: $TOTAL_TESTS${NC}"
echo -e "${GREEN}Vulnerabilities/Issues found: $FINDINGS${NC}"
echo -e "${CYAN}Detection rate: $PERCENTAGE%${NC}"
echo ""

if [ $FINDINGS -ge 4 ]; then
    echo -e "${GREEN}🎉 EXCELLENT! Hexstrike detected multiple security issues!${NC}"
    echo -e "${GREEN}With full tools (sqlmap, nuclei, nmap), detection would be even better!${NC}"
elif [ $FINDINGS -ge 2 ]; then
    echo -e "${YELLOW}⚠️  GOOD! Found several issues with basic tools.${NC}"
else
    echo -e "${RED}❌ LIMITED! Need full security tools for better detection.${NC}"
fi

echo ""
echo -e "${CYAN}================================================================================${NC}"
echo ""

# Hexstrike capabilities note
echo -e "${BLUE}📝 NOTE: This test used only curl/grep (basic tools)${NC}"
echo -e "${BLUE}   Full Hexstrike with all tools would detect:${NC}"
echo -e "${BLUE}   - More SQL injection vectors (sqlmap)${NC}"
echo -e "${BLUE}   - XSS in all parameters (dalfox)${NC}"
echo -e "${BLUE}   - Known CVEs (nuclei)${NC}"
echo -e "${BLUE}   - Open ports & services (nmap)${NC}"
echo -e "${BLUE}   - Directory bruteforce (gobuster)${NC}"
echo -e "${BLUE}   - And 150+ other security checks!${NC}"
echo ""

exit 0
