# 📋 TODO - Hexstrike-AI (Fork)

**Autor:** Seb (pentester@netcuter.com)  
**Data:** 2025-11-28  
**Cel:** Dostosowanie HexStrike AI do własnych potrzeb pentestingowych

---

## 🔍 O PROJEKCIE:

HexStrike AI to MCP server umożliwiający AI agentom (GPT, Copilot, inne AI) autonomiczne uruchamianie 150+ narzędzi cybersecurity.

**Upstream:** https://github.com/0x4m4/hexstrike-ai  
**Fork:** https://github.com/netcuter/Hexstrike-AI

---

## 📝 TODO - CUSTOMIZACJA:

### TODO-H1: Polskie komentarze i dokumentacja
```
PLIKI: *.py w głównym katalogu
ZADANIE: Dodaj polskie docstringi dla kluczowych funkcji

PRZYKŁAD:
def run_nmap_scan(target: str, options: str = "-sV"):
    """
    Wykonuje skan Nmap na podanym celu.
    
    Args:
        target: Adres IP lub hostname do skanowania
        options: Opcje Nmap (domyślnie -sV dla wykrywania wersji)
    
    Returns:
        dict: Wyniki skanowania w formacie strukturalnym
    
    Uwaga:
        Wymaga uprawnień root dla niektórych typów skanów.
    """
    pass
```

### TODO-H2: Integracja z local-custom-llm
```
PLIK: integrations/local_llm_bridge.py (NOWY)
OPIS: Most między HexStrike a lokalnym backendem Granite/Gemma

import aiohttp
import asyncio

class LocalLLMBridge:
    """
    Bridge do komunikacji z lokalnym systemem LLM.
    Używa Granite jako agent do decyzji o narzędziach.
    """
    
    AGENT_URL = "http://172.22.48.1:8087/v1/chat/completions"
    AGENT_MODEL = "ibm/granite-4-h-tiny"
    
    async def get_tool_decision(self, context: str) -> dict:
        """Zapytaj Granite które narzędzie użyć"""
        payload = {
            "model": self.AGENT_MODEL,
            "messages": [
                {"role": "system", "content": "Jesteś ekspertem pentestingu..."},
                {"role": "user", "content": context}
            ]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(self.AGENT_URL, json=payload) as resp:
                return await resp.json()
    
    async def execute_with_fallback(self, tool: str, params: dict):
        """Wykonaj narzędzie z fallback do lokalnego wykonania"""
        pass
```

### TODO-H3: Whitelist bezpiecznych narzędzi
```
PLIK: config/tool_whitelist.yaml (NOWY)
OPIS: Lista narzędzi dozwolonych bez dodatkowej autoryzacji

# Narzędzia BEZPIECZNE - można używać swobodnie
safe_tools:
  reconnaissance:
    - whois_lookup
    - dns_enum  
    - ssl_check
    - header_analysis
    - robots_txt_check
    - sitemap_fetch
  
  scanning:
    - nmap_basic          # Tylko -sT -sV, bez -sS
    - masscan_limited     # Max 100 portów
    - ping_sweep
  
  web_analysis:
    - nikto_safe          # Bez exploitów
    - dirb_common         # Tylko common.txt
    - wappalyzer

# Narzędzia WYMAGAJĄCE AUTORYZACJI - pytaj przed użyciem
require_approval:
  - sqlmap_*
  - hydra_*
  - metasploit_*
  - burp_active_*

# Narzędzia ZABLOKOWANE - nigdy nie używaj
blocked_tools:
  - exploit_*
  - payload_*
  - ransomware_*
  - ddos_*
```

### TODO-H4: Tryb dry-run
```
PLIK: hexstrike_mcp.py
LOKALIZACJA: Klasa główna / funkcja execute_tool
ZADANIE: Dodaj flagę --dry-run

IMPLEMENTACJA:
class HexStrikeMCP:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
    
    def execute_tool(self, tool_name: str, params: dict):
        command = self.build_command(tool_name, params)
        
        if self.dry_run:
            print(f"[DRY-RUN] Would execute: {command}")
            return {"status": "dry_run", "command": command}
        
        # Normalne wykonanie
        return self.run_command(command)

UŻYCIE:
python hexstrike_mcp.py --dry-run
```

### TODO-H5: Raportowanie w formacie polskim
```
PLIK: reporting/polish_report.py (NOWY)
OPIS: Generator raportów po polsku

TEMPLATE:
# RAPORT Z TESTU PENETRACYJNEGO
# Data: {date}
# Tester: {tester}
# Cel: {target}

## PODSUMOWANIE WYKONAWCZE
{executive_summary}

## ZNALEZIONE PODATNOŚCI
| Krytyczność | Nazwa | Opis | Rekomendacja |
|-------------|-------|------|--------------|
{vulnerabilities_table}

## SZCZEGÓŁY TECHNICZNE
{technical_details}

## REKOMENDACJE
{recommendations}
```

---

## 📝 TODO - BEZPIECZEŃSTWO:

### TODO-H6: Logowanie wszystkich operacji
```
PLIK: utils/audit_logger.py (NOWY)
OPIS: Pełny audit trail wszystkich wykonanych poleceń

STRUKTURA LOGU:
{
    "timestamp": "2025-11-28T12:00:00Z",
    "user": "seb",
    "tool": "nmap",
    "target": "192.168.1.0/24",
    "command": "nmap -sV 192.168.1.0/24",
    "result_hash": "sha256:...",
    "duration_sec": 45.2,
    "exit_code": 0
}
```

### TODO-H7: Weryfikacja scope przed skanowaniem
```
PLIK: utils/scope_validator.py (NOWY)
OPIS: Sprawdź czy cel jest w autoryzowanym zakresie

FUNKCJE:
- load_scope(file) - wczytaj dozwolone zakresy IP/domeny
- validate_target(target) - sprawdź czy cel jest w scope
- block_out_of_scope() - zablokuj próby skanowania poza scope

PLIK SCOPE (scope.txt):
# Autoryzowane cele
192.168.1.0/24
10.0.0.0/8
*.example.com
testsite.local
```

---

## 📝 TODO - INTEGRACJE:

### TODO-H8: Integracja z Burp Suite
```
PLIK: integrations/burp_bridge.py
OPIS: Komunikacja z Burp Suite Pro przez REST API

FUNKCJE:
- start_scan(url) - uruchom aktywny skan
- get_issues() - pobierz znalezione podatności
- export_report(format) - eksportuj raport
```

### TODO-H9: Export do DefectDojo
```
PLIK: integrations/defectdojo.py
OPIS: Automatyczny import wyników do DefectDojo

FUNKCJE:
- create_engagement()
- import_scan_results()
- update_findings()
```

---

## 🛠️ INSTRUKCJE DLA AI:

1. **ZAWSZE sprawdź scope** przed skanowaniem
2. **LOGUJ wszystko** do audit.log
3. **NIE używaj** narzędzi z listy blocked_tools
4. **PYTAJ o zgodę** dla narzędzi require_approval
5. **Testuj w dry-run** najpierw

**Etyka pentestingu:**
- Tylko autoryzowane cele
- Dokumentuj wszystko
- Raportuj odpowiedzialnie
- Nie niszcz danych

**Format commit:**
```
[hexstrike] Krótki opis

Co zostało zmienione i dlaczego.
Testowano na: [środowisko]
```

---

⚔️ PRO DEO ET PATRIA! 
Done!
