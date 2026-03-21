#!/usr/bin/env python3
"""
Hexstrike 7 PL - Tool Annotations for AI Agents
Adnotacje narzędzi dla lepszego rozumienia przez agentów AI (LM Studio, MCP, API)

PR #125 from original repo implemented here.
Na podstawie zgłoszenia #125 z oryginalnego repo.

Kompatybilne z każdym agentem AI przez MCP lub REST API:
Compatible with any AI agent via MCP or REST API:
  - Local LLMs (LM Studio, Ollama, llama.cpp)
  - Cloud LLMs via API
  - Any MCP-compatible client

Każde narzędzie ma / Each tool has:
  - description: co robi / what it does
  - use_when: kiedy użyć / when to use
  - avoid_when: kiedy NIE używać / when NOT to use
  - risk: ryzyko dla celu / risk to target (low/medium/high/critical)
  - speed: czas wykonania / execution time (fast/medium/slow/very_slow)
  - requires: wymagania / requirements
  - output_fields: co zwraca / what it returns
  - phase: faza pentestau / pentest phase

Użycie z API / API usage:
  GET /api/tools/annotations          — wszystkie adnotacje / all annotations
  GET /api/tools/annotations?phase=recon   — filtruj po fazie / filter by phase
  GET /api/tools/annotations?tool=nmap     — info o narzędziu / tool info
  GET /api/tools/workflow-guide            — przewodnik / workflow guide

Python:
  from tool_annotations import get_tool_info, suggest_tools
"""

from typing import List, Optional, Dict, Any

# ============================================================================
# TOOL ANNOTATIONS DATABASE
# ============================================================================

TOOL_ANNOTATIONS: Dict[str, Dict[str, Any]] = {

    # ──────────────────────────────────────────────────────────────
    # PORT SCANNING / NETWORK RECON
    # ──────────────────────────────────────────────────────────────

    "nmap": {
        "endpoint": "/api/tools/nmap",
        "description": "Network port scanner and service detection. Discovers open ports, running services, OS, and versions. The standard tool for network mapping.",
        "description_pl": "Skaner portów sieciowych i detekcja usług. Odkrywa otwarte porty, usługi, OS i wersje. Standardowe narzędzie do mapowania sieci.",
        "use_when": [
            "Starting a pentest - first step to map attack surface",
            "Need to know which services are running on target",
            "OS/version fingerprinting required",
            "Firewall/IDS evasion needed with stealth scans"
        ],
        "avoid_when": [
            "Target explicitly out of scope",
            "Very noisy scan types (SYN flood) on production without permission"
        ],
        "risk": "medium",
        "speed": "medium",
        "phase": ["recon", "enumeration"],
        "requires": [],
        "output_fields": ["open_ports", "services", "versions", "os_guess"],
        "params": {
            "target": "IP, hostname, or CIDR range",
            "options": "nmap flags (-sV, -sC, -A, -p-, etc.)"
        },
        "examples": [
            {"target": "192.168.1.1", "options": "-sV -sC -p 80,443,22"},
            {"target": "10.0.0.0/24", "options": "-sn"},
            {"target": "target.com", "options": "-A -T4"}
        ]
    },

    "rustscan": {
        "endpoint": "/api/tools/rustscan",
        "description": "Ultra-fast port scanner written in Rust. Much faster than nmap for initial port discovery. Use before nmap for service detection.",
        "description_pl": "Ultraszybki skaner portów w Rust. Znacznie szybszy niż nmap do wstępnego odkrywania portów.",
        "use_when": [
            "Quick initial port discovery on large networks",
            "Time-constrained assessments",
            "Scanning many hosts"
        ],
        "avoid_when": ["Need detailed service fingerprinting (use nmap instead)"],
        "risk": "medium",
        "speed": "fast",
        "phase": ["recon"],
        "requires": ["rustscan installed"],
        "output_fields": ["open_ports"],
        "params": {
            "target": "IP or hostname",
            "options": "rustscan flags"
        }
    },

    "masscan": {
        "endpoint": "/api/tools/masscan",
        "description": "Internet-scale port scanner. Extremely fast, can scan entire internet in 6 minutes at 10Mpps. Best for very large ranges.",
        "description_pl": "Skaner portów w skali internetu. Ekstremalnie szybki.",
        "use_when": [
            "Scanning very large IP ranges (Class B/C)",
            "Initial reconnaissance on huge scope"
        ],
        "avoid_when": [
            "Small targets (nmap is better)",
            "Stealth required (masscan is loud)"
        ],
        "risk": "high",
        "speed": "fast",
        "phase": ["recon"],
        "requires": ["masscan installed", "rate limit config"],
        "output_fields": ["open_ports", "banners"]
    },

    # ──────────────────────────────────────────────────────────────
    # WEB DIRECTORY/ENDPOINT DISCOVERY
    # ──────────────────────────────────────────────────────────────

    "gobuster": {
        "endpoint": "/api/tools/gobuster",
        "description": "Directory/file brute-forcer for web apps. Discovers hidden paths, backup files, admin panels, API endpoints.",
        "description_pl": "Brute-forcer katalogów i plików webowych. Odkrywa ukryte ścieżki, panele admina, endpointy API.",
        "use_when": [
            "After initial nmap - explore web attack surface",
            "Looking for hidden admin panels or config files",
            "API endpoint enumeration",
            "File extension brute-force (backup files: .bak, .old, .sql)"
        ],
        "avoid_when": [
            "Very large wordlists on slow connections",
            "When rate limiting is aggressive (use ffuf with rate control)"
        ],
        "risk": "low",
        "speed": "medium",
        "phase": ["enumeration", "web"],
        "requires": ["gobuster installed", "wordlist"],
        "output_fields": ["discovered_paths", "status_codes", "sizes"],
        "params": {
            "url": "Base URL (https://target.com)",
            "mode": "dir / dns / fuzz / vhost (default: dir)",
            "wordlist": "/usr/share/dirb/wordlists/common.txt",
            "additional_args": "-t 30 -x php,html,js -q"
        }
    },

    "ffuf": {
        "endpoint": "/api/tools/ffuf",
        "description": "Fast web fuzzer. More flexible than gobuster - supports multiple injection points (headers, POST data, query params), response filtering.",
        "description_pl": "Szybki fuzzer webowy. Bardziej elastyczny niż gobuster - wiele punktów wstrzykiwania.",
        "use_when": [
            "Parameter fuzzing (GET/POST)",
            "Virtual host discovery",
            "API endpoint fuzzing with response filtering",
            "When you need precise response size/code filtering"
        ],
        "avoid_when": ["Simple directory brute-force (gobuster is simpler)"],
        "risk": "low",
        "speed": "fast",
        "phase": ["enumeration", "web", "fuzzing"],
        "requires": ["ffuf installed"],
        "output_fields": ["discovered_paths", "status_codes", "sizes", "words", "lines"]
    },

    "dirb": {
        "endpoint": "/api/tools/dirb",
        "description": "Classic web directory scanner. Slower than gobuster/ffuf but included for compatibility.",
        "description_pl": "Klasyczny skaner katalogów webowych.",
        "use_when": ["Legacy compatibility", "When gobuster/ffuf not available"],
        "avoid_when": ["When speed matters - use gobuster or ffuf instead"],
        "risk": "low",
        "speed": "slow",
        "phase": ["enumeration", "web"],
        "requires": ["dirb installed"],
        "output_fields": ["discovered_paths"]
    },

    # ──────────────────────────────────────────────────────────────
    # WEB VULNERABILITY SCANNING
    # ──────────────────────────────────────────────────────────────

    "nikto": {
        "endpoint": "/api/tools/nikto",
        "description": "Web server scanner. Detects outdated software, dangerous files, misconfigurations, security headers issues. Noisy but comprehensive.",
        "description_pl": "Skaner serwera webowego. Wykrywa przestarzałe oprogramowanie, niebezpieczne pliki, błędy konfiguracji.",
        "use_when": [
            "Web server assessment",
            "Checking for known CVEs in web server",
            "Security headers audit",
            "Checking for default files/configs"
        ],
        "avoid_when": [
            "Stealth required (very noisy, leaves obvious logs)",
            "Modern well-maintained servers (high FP rate)"
        ],
        "risk": "medium",
        "speed": "slow",
        "phase": ["web", "vulnerability_scanning"],
        "requires": ["nikto installed"],
        "output_fields": ["vulnerabilities", "server_info", "headers", "ssl_info"]
    },

    "nuclei": {
        "endpoint": "/api/tools/nuclei",
        "description": "Template-based vulnerability scanner. 9000+ templates for CVEs, misconfigs, exposed panels, default credentials. Best automated vuln scanner.",
        "description_pl": "Skaner podatności oparty na szablonach. 9000+ szablonów na CVE, błędy konfiguracji, domyślne dane logowania.",
        "use_when": [
            "Automated vulnerability discovery",
            "CVE-specific scanning",
            "Technology-specific checks",
            "Exposed panel detection",
            "Default credential testing"
        ],
        "avoid_when": ["Need manual/contextual testing"],
        "risk": "medium",
        "speed": "medium",
        "phase": ["vulnerability_scanning"],
        "requires": ["nuclei installed", "templates updated"],
        "output_fields": ["vulnerabilities", "template_id", "severity", "matched_at"],
        "params": {
            "target": "URL or host",
            "options": "-t cves/ -severity high,critical -rate-limit 100"
        }
    },

    "sqlmap": {
        "endpoint": "/api/tools/sqlmap",
        "description": "Automated SQL injection detection and exploitation. Tests for SQLi, dumps databases, can escalate to OS shell.",
        "description_pl": "Automatyczna detekcja i eksploitacja SQL injection. Testuje SQLi, zrzuca bazy, może eskalować do shella OS.",
        "use_when": [
            "Suspected SQL injection in form/parameter",
            "Database content extraction after confirmed SQLi",
            "Testing all parameters of a target URL"
        ],
        "avoid_when": [
            "Without explicit permission - can damage databases",
            "Production databases without backup"
        ],
        "risk": "high",
        "speed": "slow",
        "phase": ["exploitation", "web"],
        "requires": ["sqlmap installed"],
        "output_fields": ["injectable_params", "dbms", "databases", "tables", "data"],
        "params": {
            "url": "Target URL with parameter (http://target.com/page?id=1)",
            "options": "--batch --dbs --risk=2 --level=3"
        }
    },

    "wpscan": {
        "endpoint": "/api/tools/wpscan",
        "description": "WordPress security scanner. Enumerates plugins, themes, users, checks for known vulnerabilities.",
        "description_pl": "Skaner bezpieczeństwa WordPress. Enumeruje pluginy, motywy, użytkowników, sprawdza znane podatności.",
        "use_when": [
            "Target is a WordPress site",
            "WordPress plugin/theme vulnerability check",
            "WordPress user enumeration"
        ],
        "avoid_when": ["Target is not WordPress"],
        "risk": "medium",
        "speed": "medium",
        "phase": ["enumeration", "vulnerability_scanning"],
        "requires": ["wpscan installed"],
        "output_fields": ["version", "plugins", "themes", "users", "vulnerabilities"]
    },

    # ──────────────────────────────────────────────────────────────
    # SUBDOMAIN / DNS RECON
    # ──────────────────────────────────────────────────────────────

    "subfinder": {
        "endpoint": "/api/tools/subfinder",
        "description": "Passive subdomain discovery using multiple sources (VirusTotal, Shodan, cert.sh, etc.). Fast and passive.",
        "description_pl": "Pasywne odkrywanie subdomen z wielu źródeł. Szybkie i pasywne.",
        "use_when": [
            "First step in web app recon",
            "Expanding attack surface to subdomains",
            "Passive recon (no direct target contact)"
        ],
        "avoid_when": ["Need active DNS brute-force (use amass instead)"],
        "risk": "low",
        "speed": "fast",
        "phase": ["recon"],
        "requires": ["subfinder installed"],
        "output_fields": ["subdomains"]
    },

    "amass": {
        "endpoint": "/api/tools/amass",
        "description": "Comprehensive attack surface mapping - active and passive subdomain enumeration, DNS brute-force, ASN mapping.",
        "description_pl": "Kompleksowe mapowanie powierzchni ataku - aktywne i pasywne odkrywanie subdomen.",
        "use_when": [
            "Thorough subdomain enumeration needed",
            "ASN/IP range mapping",
            "DNS brute-force"
        ],
        "avoid_when": ["Quick passive recon only (use subfinder)"],
        "risk": "medium",
        "speed": "very_slow",
        "phase": ["recon"],
        "requires": ["amass installed"],
        "output_fields": ["subdomains", "asns", "ip_ranges", "dns_records"]
    },

    # ──────────────────────────────────────────────────────────────
    # PASSWORD / AUTH ATTACKS
    # ──────────────────────────────────────────────────────────────

    "hydra": {
        "endpoint": "/api/tools/hydra",
        "description": "Online password brute-forcer. Supports 50+ protocols: SSH, FTP, HTTP, SMB, RDP, MySQL, etc.",
        "description_pl": "Narzędzie do brute-force haseł online. Obsługuje 50+ protokołów: SSH, FTP, HTTP, SMB, RDP, MySQL.",
        "use_when": [
            "Testing for weak/default credentials",
            "Password spraying on login forms",
            "SSH/FTP brute-force"
        ],
        "avoid_when": [
            "Account lockout policies active - check first",
            "Without permission - can lock accounts/trigger alerts"
        ],
        "risk": "high",
        "speed": "medium",
        "phase": ["exploitation"],
        "requires": ["hydra installed", "wordlist"],
        "output_fields": ["valid_credentials", "service"]
    },

    "john": {
        "endpoint": "/api/tools/john",
        "description": "Offline password hash cracker (John the Ripper). Cracks hashed passwords from /etc/shadow, hash dumps, zip/pdf/office files.",
        "description_pl": "Narzędzie do łamania hashy haseł offline.",
        "use_when": [
            "After obtaining password hashes (from sqlmap, shadow file, etc.)",
            "Cracking zip/pdf/office file passwords",
            "Testing password strength"
        ],
        "avoid_when": ["Online attacks (use hydra)"],
        "risk": "low",
        "speed": "slow",
        "phase": ["post_exploitation"],
        "requires": ["john installed", "wordlist", "obtained hashes"],
        "output_fields": ["cracked_passwords"]
    },

    "hashcat": {
        "endpoint": "/api/tools/hashcat",
        "description": "GPU-accelerated password hash cracker. Much faster than John for large hash sets. Supports 300+ hash types.",
        "description_pl": "Łamacz hashy z akceleracją GPU. Znacznie szybszy od Johna przy dużych zbiorach hashy.",
        "use_when": [
            "Large number of hashes to crack",
            "GPU available for acceleration",
            "Complex hash types (bcrypt, WPA, NTLM)"
        ],
        "avoid_when": ["No GPU (john may be similar speed on CPU)"],
        "risk": "low",
        "speed": "slow",
        "phase": ["post_exploitation"],
        "requires": ["hashcat installed", "wordlist", "GPU preferred"]
    },

    # ──────────────────────────────────────────────────────────────
    # SMB / WINDOWS / AD ENUMERATION
    # ──────────────────────────────────────────────────────────────

    "enum4linux": {
        "endpoint": "/api/tools/enum4linux",
        "description": "SMB/NetBIOS enumeration for Windows/Samba targets. Lists shares, users, groups, policies via null sessions.",
        "description_pl": "Enumeracja SMB/NetBIOS dla celów Windows/Samba. Lista udziałów, użytkowników, grup.",
        "use_when": [
            "Windows/Samba target with SMB (port 139/445) open",
            "Active Directory enumeration",
            "Checking for null session access"
        ],
        "avoid_when": ["Non-Windows targets"],
        "risk": "medium",
        "speed": "fast",
        "phase": ["enumeration"],
        "requires": ["enum4linux installed", "SMB port 139/445 open"],
        "output_fields": ["shares", "users", "groups", "policies", "os_info"]
    },

    "smbmap": {
        "endpoint": "/api/tools/smbmap",
        "description": "SMB share enumeration and access checking. Lists readable/writable shares with credentials or null session.",
        "description_pl": "Enumeracja udziałów SMB i sprawdzanie dostępu.",
        "use_when": [
            "Checking SMB share permissions",
            "File enumeration on accessible shares",
            "Testing with obtained credentials"
        ],
        "avoid_when": ["No SMB port open"],
        "risk": "medium",
        "speed": "fast",
        "phase": ["enumeration"],
        "requires": ["smbmap installed", "SMB access"]
    },

    "netexec": {
        "endpoint": "/api/tools/netexec",
        "description": "Network exploitation framework (nxc, formerly CrackMapExec). Tests credentials across large networks, SMB relay, pass-the-hash.",
        "description_pl": "Framework eksploracji sieci (następca CrackMapExec). Testuje dane logowania w sieci.",
        "use_when": [
            "After obtaining credentials - test where they work",
            "Password spraying across Windows network",
            "Pass-the-hash attacks",
            "SMB/WinRM/LDAP lateral movement"
        ],
        "avoid_when": ["Without valid credentials or explicit permission"],
        "risk": "high",
        "speed": "fast",
        "phase": ["exploitation", "post_exploitation"],
        "requires": ["netexec/nxc installed", "credentials or hashes"]
    },

    # ──────────────────────────────────────────────────────────────
    # CLOUD SECURITY
    # ──────────────────────────────────────────────────────────────

    "prowler": {
        "endpoint": "/api/tools/prowler",
        "description": "AWS/Azure/GCP security assessment. Checks 400+ CIS/NIST/SOC2 controls. Best for cloud config audit.",
        "description_pl": "Ocena bezpieczeństwa AWS/Azure/GCP. Sprawdza 400+ kontrolek CIS/NIST/SOC2.",
        "use_when": [
            "Cloud infrastructure security audit",
            "CIS benchmark compliance check",
            "AWS misconfiguration discovery"
        ],
        "avoid_when": ["Non-cloud targets"],
        "risk": "low",
        "speed": "slow",
        "phase": ["enumeration", "vulnerability_scanning"],
        "requires": ["prowler installed", "cloud credentials configured"]
    },

    "trivy": {
        "endpoint": "/api/tools/trivy",
        "description": "Container and IaC vulnerability scanner. Scans Docker images, Kubernetes, Terraform, Helm for CVEs and misconfigs.",
        "description_pl": "Skaner podatności kontenerów i IaC.",
        "use_when": [
            "Docker image CVE scanning",
            "Kubernetes misconfiguration check",
            "Terraform/IaC security review"
        ],
        "avoid_when": ["Traditional web/network targets"],
        "risk": "low",
        "speed": "medium",
        "phase": ["vulnerability_scanning"],
        "requires": ["trivy installed"]
    },

    # ──────────────────────────────────────────────────────────────
    # AI/INTELLIGENCE ENDPOINTS
    # ──────────────────────────────────────────────────────────────

    "analyze-target": {
        "endpoint": "/api/intelligence/analyze-target",
        "description": "AI analysis of target - detects technologies, calculates attack surface, determines risk level. Use BEFORE selecting tools.",
        "description_pl": "Analiza celu przez AI - wykrywa technologie, oblicza powierzchnię ataku. Użyj PRZED wyborem narzędzi.",
        "use_when": [
            "First analysis of unknown target",
            "Need intelligent tool recommendations",
            "Technology stack detection"
        ],
        "avoid_when": ["Already know the target well"],
        "risk": "low",
        "speed": "medium",
        "phase": ["recon"],
        "requires": [],
        "output_fields": ["target_type", "technologies", "attack_surface_score", "recommended_tools", "risk_level"]
    },

    "smart-scan": {
        "endpoint": "/api/intelligence/smart-scan",
        "description": "Fully autonomous AI-driven scan. Analyzes target, selects tools, executes attack chain, returns aggregated results. Best for automated pentesting.",
        "description_pl": "W pełni autonomiczny skan sterowany przez AI. Analizuje cel, dobiera narzędzia, wykonuje łańcuch ataków.",
        "use_when": [
            "Want fully automated pentest",
            "Don't know where to start",
            "Need comprehensive results quickly"
        ],
        "avoid_when": ["Need precise control over each step"],
        "risk": "high",
        "speed": "very_slow",
        "phase": ["recon", "enumeration", "vulnerability_scanning"],
        "requires": [],
        "output_fields": ["recon_results", "vulnerabilities", "attack_chain", "recommendations"]
    },

    "select-tools": {
        "endpoint": "/api/intelligence/select-tools",
        "description": "AI tool selector - given target profile and objective, returns prioritized list of optimal tools with parameters.",
        "description_pl": "Selektor narzędzi AI - dla danego profilu celu zwraca listę optymalnych narzędzi z parametrami.",
        "use_when": ["Not sure which tool to use for a target/objective"],
        "avoid_when": ["Already have a plan"],
        "risk": "low",
        "speed": "fast",
        "phase": ["planning"],
        "requires": [],
        "output_fields": ["recommended_tools", "parameters", "rationale"]
    },

    # ──────────────────────────────────────────────────────────────
    # SESSION MANAGER (v7 PL - new)
    # ──────────────────────────────────────────────────────────────

    "session-create": {
        "endpoint": "/api/session/create",
        "description": "Create a pentest session for a target. Stores all findings persistently across tool runs. Essential for multi-session engagements.",
        "description_pl": "Utwórz sesję pentestową dla celu. Przechowuje wszystkie wyniki między uruchomieniami narzędzi.",
        "use_when": [
            "Starting a new engagement",
            "Want to track findings from multiple tools",
            "Need to generate a final report"
        ],
        "avoid_when": ["Quick one-off check without reporting"],
        "risk": "low",
        "speed": "fast",
        "phase": ["planning"],
        "requires": [],
        "output_fields": ["session_id"],
        "params": {
            "target": "Target URL/IP",
            "name": "Engagement name",
            "scope": "Scope definition",
            "tester": "Tester name"
        }
    },

    "session-report": {
        "endpoint": "/api/session/{session_id}/report",
        "description": "Generate full markdown pentest report from session data. Includes executive summary, CVSS scores, findings table, remediation priorities.",
        "description_pl": "Generuj pełny raport pentestowy z danych sesji. Zawiera executive summary, CVSS, tabelę wyników, priorytety remediacji.",
        "use_when": [
            "At end of engagement",
            "After adding all findings to session",
            "Need deliverable for client/bug bounty platform"
        ],
        "avoid_when": ["Session is empty (no findings yet)"],
        "risk": "low",
        "speed": "fast",
        "phase": ["reporting"],
        "requires": ["active session with findings"],
        "output_fields": ["markdown_report", "executive_summary", "risk_score"]
    },

    # ──────────────────────────────────────────────────────────────
    # VULNERABILITY INTELLIGENCE
    # ──────────────────────────────────────────────────────────────

    "cve-monitor": {
        "endpoint": "/api/vuln-intel/cve-monitor",
        "description": "Fetch latest CVEs from NVD. Filter by severity and time range. Use to stay current on relevant vulnerabilities.",
        "description_pl": "Pobierz najnowsze CVE z NVD. Filtruj po severity i czasie.",
        "use_when": [
            "Checking for recent CVEs affecting a technology",
            "Staying current on critical vulnerabilities",
            "Before starting assessment - what's new for this tech stack"
        ],
        "avoid_when": ["Need CVE details for specific version (use analyze-cve)"],
        "risk": "low",
        "speed": "medium",
        "phase": ["recon", "planning"],
        "requires": ["internet access"],
        "output_fields": ["cves", "cvss_scores", "descriptions", "references"]
    },

    "exploit-generate": {
        "endpoint": "/api/vuln-intel/exploit-generate",
        "description": "Generate exploit code from CVE data using AI. Supports SQLi, XSS, RCE, XXE, buffer overflow, auth bypass.",
        "description_pl": "Generuj kod exploita z danych CVE używając AI.",
        "use_when": [
            "Need PoC for a confirmed vulnerability",
            "CVE research - need working exploit",
            "Testing exploitability of a specific CVE"
        ],
        "avoid_when": ["Without clear authorization - use responsibly"],
        "risk": "critical",
        "speed": "fast",
        "phase": ["exploitation"],
        "requires": ["CVE ID", "target info"],
        "output_fields": ["exploit_code", "instructions", "evasion_techniques"]
    },

    # ──────────────────────────────────────────────────────────────
    # BUG BOUNTY WORKFLOWS
    # ──────────────────────────────────────────────────────────────

    "recon-workflow": {
        "endpoint": "/api/bugbounty/reconnaissance-workflow",
        "description": "Complete bug bounty recon workflow: subdomain enum, port scan, web discovery, tech detection. Chains multiple tools automatically.",
        "description_pl": "Kompletny workflow recon dla bug bounty: enumeracja subdomen, skan portów, odkrywanie webowe.",
        "use_when": ["Starting bug bounty on new target", "Need complete recon in one step"],
        "avoid_when": ["Outside authorized scope"],
        "risk": "medium",
        "speed": "very_slow",
        "phase": ["recon"],
        "requires": [],
        "output_fields": ["subdomains", "ports", "web_paths", "technologies"]
    },

    "vuln-hunting": {
        "endpoint": "/api/bugbounty/vulnerability-hunting-workflow",
        "description": "Automated vulnerability hunting after recon. Runs nuclei, nikto, sqlmap, XSS detection on discovered endpoints.",
        "description_pl": "Automatyczne polowanie na podatności po recon. Uruchamia nuclei, nikto, sqlmap na odkrytych endpointach.",
        "use_when": ["After recon completed", "Have list of endpoints to test"],
        "avoid_when": ["Without completed recon first"],
        "risk": "high",
        "speed": "very_slow",
        "phase": ["vulnerability_scanning"],
        "requires": ["completed recon"],
        "output_fields": ["vulnerabilities", "severity_breakdown", "recommendations"]
    },

    # ──────────────────────────────────────────────────────────────
    # GENERAL
    # ──────────────────────────────────────────────────────────────

    "command": {
        "endpoint": "/api/command",
        "description": "Execute any shell command directly. Use for custom tools, scripts, or operations not covered by dedicated endpoints.",
        "description_pl": "Wykonaj dowolną komendę shell. Użyj dla własnych narzędzi i skryptów.",
        "use_when": [
            "Custom tool or script",
            "One-off command not in dedicated endpoints",
            "Chaining commands with pipes"
        ],
        "avoid_when": ["Dedicated endpoint exists for the tool - use specific endpoint for better params"],
        "risk": "high",
        "speed": "varies",
        "phase": ["any"],
        "requires": [],
        "params": {
            "command": "Shell command to execute",
            "timeout": "Timeout in seconds (default: 300)"
        }
    },
}

# ============================================================================
# HELPER FUNCTIONS / FUNKCJE POMOCNICZE
# ============================================================================

def get_tool_info(tool_name: str) -> Optional[Dict[str, Any]]:
    """
    Pobierz pełne info o narzędziu / Get full tool info.

    Args:
        tool_name: Nazwa narzędzia (np. 'nmap', 'sqlmap') / Tool name

    Returns:
        Dict z adnotacjami lub None jeśli nie znaleziono / Dict with annotations or None
    """
    return TOOL_ANNOTATIONS.get(tool_name.lower())


def suggest_tools(
    phase: Optional[str] = None,
    risk_max: Optional[str] = None,
    speed: Optional[str] = None,
    keyword: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Zasugeruj narzędzia na podstawie kryteriów / Suggest tools based on criteria.

    Args:
        phase: Faza pentestau / Pentest phase
               ('recon', 'enumeration', 'web', 'vulnerability_scanning',
                'exploitation', 'post_exploitation', 'reporting', 'planning')
        risk_max: Maksymalne ryzyko / Max risk ('low', 'medium', 'high', 'critical')
        speed: Wymagana szybkość / Required speed ('fast', 'medium', 'slow', 'very_slow')
        keyword: Słowo kluczowe w opisie / Keyword in description

    Returns:
        Lista narzędzi spełniających kryteria / List of matching tools

    Example:
        # Tools for recon that are low risk
        suggest_tools(phase='recon', risk_max='low')

        # Fast web tools
        suggest_tools(phase='web', speed='fast')
    """
    RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    SPEED_LEVELS = {"fast": 0, "medium": 1, "slow": 2, "very_slow": 3}

    risk_threshold = RISK_LEVELS.get(risk_max, 99) if risk_max else 99
    speed_threshold = SPEED_LEVELS.get(speed, 99) if speed else 99

    results = []
    for name, info in TOOL_ANNOTATIONS.items():
        # Filter by phase
        if phase and phase not in info.get("phase", []):
            continue

        # Filter by risk
        tool_risk = RISK_LEVELS.get(info.get("risk", "low"), 0)
        if tool_risk > risk_threshold:
            continue

        # Filter by speed
        tool_speed = SPEED_LEVELS.get(info.get("speed", "medium"), 1)
        if tool_speed > speed_threshold:
            continue

        # Filter by keyword
        if keyword:
            kw = keyword.lower()
            desc = (info.get("description", "") + info.get("description_pl", "")).lower()
            if kw not in desc and kw not in name.lower():
                continue

        results.append({
            "name": name,
            "endpoint": info["endpoint"],
            "description": info["description"],
            "risk": info.get("risk"),
            "speed": info.get("speed"),
            "phase": info.get("phase"),
        })

    return results


def get_workflow_guide() -> str:
    """
    Przewodnik po fazach pentestau / Pentest phase workflow guide.
    Designed for LLM context - explains what to run and in what order.

    Returns:
        Markdown string z przewodnikiem / Markdown guide
    """
    return """
# Hexstrike 7 PL - Workflow Guide for Claude Code

## Typowy workflow pentestowy / Typical Pentest Workflow

### Faza 1: Planning
- POST /api/session/create         — utwórz sesję
- POST /api/intelligence/analyze-target — analiza celu
- POST /api/intelligence/select-tools   — dobór narzędzi

### Faza 2: Recon (niskie ryzyko / low risk)
- POST /api/tools/subfinder        — pasywne subdomeny
- POST /api/tools/amass            — aktywne subdomeny + DNS
- POST /api/tools/nmap             — porty i usługi
- POST /api/tools/rustscan         — szybkie skanowanie portów

### Faza 3: Enumeration (średnie ryzyko / medium risk)
- POST /api/tools/gobuster         — web directories
- POST /api/tools/ffuf             — fuzzing parametrów
- POST /api/tools/nikto            — web server check
- POST /api/tools/wpscan           — jeśli WordPress
- POST /api/tools/enum4linux       — jeśli SMB/Windows

### Faza 4: Vulnerability Scanning
- POST /api/tools/nuclei           — skan CVE + szablony
- POST /api/intelligence/smart-scan — autonomiczny skan AI
- POST /api/vuln-intel/cve-monitor  — nowe CVE dla technologii

### Faza 5: Exploitation
- POST /api/tools/sqlmap           — SQL injection
- POST /api/tools/hydra            — brute-force
- POST /api/vuln-intel/exploit-generate — exploit z CVE

### Faza 6: Reporting
- POST /api/session/{id}/finding   — dodaj każdy wynik
- GET  /api/session/{id}/report    — wygeneruj raport

## Quick API reference

All endpoints: POST with JSON body to http://localhost:8888
Authentication: optional API key in X-API-Key header

## Claude Code usage example / Przykład użycia z Claude Code

```bash
# 1. Utwórz sesję
curl -X POST http://localhost:8888/api/session/create \\
  -H "Content-Type: application/json" \\
  -d '{"target": "target.com", "name": "Bug Bounty - target.com"}'

# 2. Skan nmap
curl -X POST http://localhost:8888/api/tools/nmap \\
  -H "Content-Type: application/json" \\
  -d '{"target": "target.com", "options": "-sV -sC -p 80,443,8080"}'

# 3. Dodaj wynik do sesji
curl -X POST http://localhost:8888/api/session/SESSION_ID/finding \\
  -H "Content-Type: application/json" \\
  -d '{"tool": "nmap", "vuln_type": "exposed service", "title": "Port 8080 exposed", "endpoint": "target.com:8080"}'

# 4. Raport
curl http://localhost:8888/api/session/SESSION_ID/report?format=markdown
```
"""


def register_annotations_endpoint(app):
    """
    Zarejestruj endpoint /api/tools/annotations w Flask app.
    Register /api/tools/annotations endpoint with Flask app.

    Umożliwia LLM dynamiczne pobranie opisu narzędzi.
    Allows LLM to dynamically fetch tool descriptions.
    """
    from flask import jsonify, request

    @app.route("/api/tools/annotations", methods=["GET"])
    def get_annotations():
        """
        Zwróć adnotacje narzędzi dla LLM / Return tool annotations for LLM.

        Query params:
          ?phase=recon          — filtruj po fazie / filter by phase
          ?risk_max=medium      — max ryzyko / max risk
          ?tool=nmap            — info o konkretnym narzędziu / specific tool info
          ?workflow=true        — pokaż przewodnik / show workflow guide
        """
        tool = request.args.get("tool")
        phase = request.args.get("phase")
        risk_max = request.args.get("risk_max")
        speed = request.args.get("speed")
        keyword = request.args.get("keyword")
        workflow = request.args.get("workflow") == "true"

        if workflow:
            return jsonify({
                "success": True,
                "workflow_guide": get_workflow_guide()
            })

        if tool:
            info = get_tool_info(tool)
            if not info:
                return jsonify({
                    "success": False,
                    "error": f"Tool '{tool}' not found in annotations",
                    "available_tools": list(TOOL_ANNOTATIONS.keys())
                }), 404
            return jsonify({"success": True, "tool": tool, "annotation": info})

        if any([phase, risk_max, speed, keyword]):
            results = suggest_tools(phase=phase, risk_max=risk_max,
                                    speed=speed, keyword=keyword)
            return jsonify({
                "success": True,
                "filters": {"phase": phase, "risk_max": risk_max,
                            "speed": speed, "keyword": keyword},
                "count": len(results),
                "tools": results
            })

        # Return all annotations
        return jsonify({
            "success": True,
            "total_tools": len(TOOL_ANNOTATIONS),
            "annotations": TOOL_ANNOTATIONS,
            "usage_tip": "Use ?phase=recon, ?risk_max=low, ?tool=nmap, or ?workflow=true"
        })

    @app.route("/api/tools/workflow-guide", methods=["GET"])
    def get_workflow_guide_endpoint():
        """Zwróć przewodnik po workflow / Return workflow guide"""
        return jsonify({
            "success": True,
            "workflow_guide": get_workflow_guide()
        })
