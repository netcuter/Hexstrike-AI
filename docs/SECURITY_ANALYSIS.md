# Analiza zabezpieczeń Hexstrike 7 PL

## 🔍 Executive Summary

Hexstrike 7 PL dodał warstwy zabezpieczeń (command validation, sanitization, whitelist), które **nie pasują do filozofii narzędzia pentestingowego sterowanego przez LLM**.

## ⚖️ Analiza techniczna

### 1. Command Validation (validate_command)

**Lokalizacja:** `security_utils.py:68-103`, używane w:
- `hexstrike_server.py:9304` - `/api/command` endpoint
- `hexstrike_server.py:16868` - `/api/process/execute-async` endpoint

**Mechanizm:**
```python
# Sprawdza DANGEROUS_PATTERNS:
r"rm\s+-rf\s+/"      # blokuje rm -rf /
r"mkfs\."            # blokuje format filesystem
r":\(\)\{.*\|.*&\}"  # blokuje fork bomb

# Sprawdza WHITELIST (~150 narzędzi):
if base_command not in ALLOWED_SECURITY_TOOLS:
    return False
```

**Problemy:**
- ✅ Przepuszcza: `nmap target.com | grep open` (sprawdza tylko "nmap")
- ✅ Przepuszcza: `python3 -c "import os; os.system('rm -rf /')"`
- ❌ Blokuje: `./custom_exploit.sh` (nie ma na whiteliście)
- ❌ Blokuje: `bash -c "cd /tmp && rm test"` (zawiera "rm -rf /")

### 2. Parameter Sanitization (sanitize_parameter)

**Lokalizacja:** `security_utils.py:104-127`

**Mechanizm:**
```python
dangerous_chars = [';', '|', '&', '\n', '\r', '`', '$']
# Usuwa te znaki z parametrów
```

**KRYTYCZNY PROBLEM:**
❌ **Funkcja jest ZAIMPORTOWANA ale NIGDY NIE UŻYWANA!**

```bash
$ grep -n "sanitize_parameter(" hexstrike_server.py
65:from security_utils import validate_command, sanitize_parameter, parse_command_safely
# ← tylko import, ZERO wywołań!
```

### 3. Wykonanie komendy (EnhancedCommandExecutor)

**Lokalizacja:** `hexstrike_server.py:7014-7021`

```python
self.process = subprocess.Popen(
    self.command,
    shell=True,  # ← UŻYWA SHELL!
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
```

**Problem:** Używa `shell=True` więc command injection jest nadal możliwe, mimo walidacji!

## 🎯 Konflikt z celem projektu

### Hexstrike jest narzędziem OFENSYWNYM:
- Jego zadanie: wykonywać exploitation commands generowane przez LLM
- LLM MUSI mieć możliwość generowania payloadów z pipes, redirects, command chaining
- Whitelista blokuje custom exploits i nowe narzędzia

### Przykłady LEGALNYCH komend które są blokowane lub utrudnione:

```bash
# CTF: command chaining
❌ nmap -p- target.com && nikto -h target.com

# Exploitation: pipes
❌ msfvenom -p linux/x64/shell_reverse_tcp | base64

# Custom tools
❌ ./custom_exploit.py target.com

# Cleanup (potrzebne w pentestingu)
❌ rm -rf /tmp/exploit_output && mkdir /tmp/exploit_output
```

## 💡 Rekomendacje

### ✅ ZOSTAW (to ma sens):
1. **Rate limiting** - ochrona przed DoS
2. **API authentication** - podstawowe zabezpieczenie
3. **Blokowanie fork bomb** - ochrona przed przypadkowym DoS
4. **Blokowanie `mkfs`** - ochrona przed formatowaniem dysków

### ❌ USUŃ (to psuje funkcjonalność):
1. **Whitelist narzędzi** - zbyt restrykcyjna dla pentestingu
2. **Blokowanie `rm -rf /tmp/*`** - pentesterzy muszą czyścić foldery
3. **Sanityzacja `|`, `;`, `&`** - niszczy pentestingowe komendy (i tak nieużywana)

### 🔧 OPCJONALNIE (dla zaawansowanych):
Jeśli NAPRAWDĘ chcesz zabezpieczeń:

1. **Tryb pracy:**
```bash
export HEXSTRIKE_MODE=production  # strict validation
export HEXSTRIKE_MODE=pentest     # minimal validation (default)
export HEXSTRIKE_MODE=development # no validation
```

2. **Blacklist zamiast whitelist:**
```python
FORBIDDEN_COMMANDS = ['mkfs', 'dd if=/dev/zero', 'reboot', 'shutdown']
FORBIDDEN_PATTERNS = [r':\(\)\{.*\|.*&\}']  # tylko fork bomb
# Wszystko inne: DOZWOLONE
```

3. **Disable shell=True i użyj array:**
```python
# Zamiast:
subprocess.Popen(command, shell=True)

# Użyj:
subprocess.Popen(shlex.split(command), shell=False)
# To FAKTYCZNIE chroni przed command injection
```

## 📊 Testy bezpieczeństwa

### Test 1: Bypass whitelist
```bash
✅ /usr/bin/nmap -sV target.com  # pełna ścieżka - działa!
✅ python3 -c "import os; os.system('id')"  # python na whiteliście
```

### Test 2: Pipes i chaining
```bash
✅ nmap target.com | grep open  # działa (sprawdza tylko "nmap")
❌ nmap target.com && echo done  # nie działa (pattern check)
```

### Test 3: Custom tools
```bash
❌ ./my_exploit.sh  # nie działa (whitelist)
❌ /home/user/tools/custom_scanner  # nie działa (whitelist)
```

## 🏁 Konkluzja

Dodane zabezpieczenia w Hexstrike 7 PL są **nadmiarowe i sprzeczne z celem projektu**:

1. **Nie chronią faktycznie** - używają `shell=True` więc command injection nadal możliwe
2. **Blokują legalne użycie** - whitelist i patterns blokują pentestingowe komendy
3. **Nie są spójne** - sanitize_parameter nie jest używane
4. **Konflikt filozoficzny** - narzędzie ofensywne z defensywnymi zabezpieczeniami

### Porównanie z oryginalnym Hexstrike AI v6.0:
- **Oryginalny:** Zero walidacji, pełna elastyczność, trust LLM
- **Fork 7 PL:** Walidacja, whitelist, sanitization (nieużywana)

**Zalecenie:** Rozważ usunięcie większości zabezpieczeń i zostaw tylko rate limiting + API auth.
