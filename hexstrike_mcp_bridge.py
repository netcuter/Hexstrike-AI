#!/usr/bin/env python3
"""
HexStrike MCP Bridge z SECURE anonimizacja
Mapping w zewnetrznym pliku - AI Assistant NIE MA dostepu!
"""

import json
import sys
import re
import requests
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Set

# SCIEZKI DO SENSITIVE DATA (poza repo!)
SENSITIVE_DIR = Path.home() / ".hexstrike_sensitive"
MAPPING_FILE = SENSITIVE_DIR / "mapping.json"
WHITELIST_FILE = SENSITIVE_DIR / "whitelist.txt"
REAL_TARGETS_FILE = SENSITIVE_DIR / "real_targets.txt"
LOG_DIR = SENSITIVE_DIR / "logs"

# LOGGING SETUP
LOG_DIR.mkdir(parents=True, exist_ok=True)
log_file = LOG_DIR / f"mcp_bridge_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stderr)
    ]
)

logger = logging.getLogger(__name__)


class SecureAnonymizationEngine:
    """Anonimizacja z external config - AI Assistant nie widzi prawdziwych domen!"""
    
    def __init__(self):
        self.mapping_file = MAPPING_FILE
        self.whitelist_file = WHITELIST_FILE
        self.real_targets_file = REAL_TARGETS_FILE
        self.mapping: Dict[str, str] = {}
        self.whitelist: Set[str] = set()
        self.real_targets: Set[str] = set()
        self.counter = 0
        
        self._load_config()
        
    def _load_config(self):
        """Load mapping, whitelist i real targets"""
        
        # Load whitelist (NIE anonimizowane)
        if self.whitelist_file.exists():
            with open(self.whitelist_file, 'r') as f:
                self.whitelist = {line.strip() for line in f if line.strip()}
            logger.info(f"Loaded {len(self.whitelist)} whitelisted domains")
        else:
            self.whitelist = {'127.0.0.1', 'localhost', 'target.test'}
            logger.info("Using default whitelist")
        
        # Load real targets (BEDA anonimizowane!)
        if self.real_targets_file.exists():
            with open(self.real_targets_file, 'r') as f:
                self.real_targets = {line.strip() for line in f if line.strip()}
            logger.warning(f"Loaded {len(self.real_targets)} REAL TARGETS (will be anonymized)")
            for target in self.real_targets:
                logger.warning(f"  [REAL] Real target: {target}")
        else:
            logger.info("No real targets file found")
        
        # Load mapping
        if self.mapping_file.exists():
            try:
                with open(self.mapping_file, 'r') as f:
                    self.mapping = json.load(f)
                self.counter = len(self.mapping)
                logger.info(f"Loaded {len(self.mapping)} existing mappings")
            except:
                self.mapping = {}
                logger.info("Starting with empty mapping")
        else:
            self.mapping = {}
            logger.info("No existing mapping found")
    
    def _save_mapping(self):
        """Zapisz mapping do pliku"""
        try:
            SENSITIVE_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.mapping_file, 'w') as f:
                json.dump(self.mapping, f, indent=2)
            os.chmod(self.mapping_file, 0o600)
            logger.debug(f"Saved {len(self.mapping)} mappings")
        except Exception as e:
            logger.error(f"Error saving mapping: {e}")
    
    def _is_whitelisted(self, value: str) -> bool:
        """Check czy wartosc jest na whiteliscie (NIE anonimizowac)"""
        return any(wl in value.lower() for wl in self.whitelist)
    
    def _is_real_target(self, value: str) -> bool:
        """Check czy wartosc jest prawdziwym celem (ANONIMIZOWAC!)"""
        return any(target in value.lower() for target in self.real_targets)
    
    def anonymize(self, text: str) -> str:
        """Anonimizuje sensitive data"""
        if not isinstance(text, str):
            return text
        
        changed = False
        original_text = text
        
        # URLs/Domains
        for match in re.finditer(r'https?://([a-z0-9\-\.]+(?:\.[a-z]{2,})?(?::\d+)?)', text, re.I):
            domain = match.group(1)
            full_url = match.group(0)
            
            # Skip whitelisted (localhost, etc.)
            if self._is_whitelisted(domain):
                logger.debug(f"[WHITELIST] Not anonymized: {domain}")
                continue
            
            # Anonymize real targets!
            if self._is_real_target(domain):
                if domain not in self.mapping:
                    self.mapping[domain] = f"target{self.counter}.test"
                    self.counter += 1
                    changed = True
                    logger.warning(f"[REAL TARGET] ANONYMIZED: {domain} -> {self.mapping[domain]}")
                
                anon_url = full_url.replace(domain, self.mapping[domain])
                text = text.replace(full_url, anon_url)
                logger.info(f"   Replaced: {full_url} -> {anon_url}")
            
            # Also anonymize unknown domains
            elif domain not in self.whitelist:
                if domain not in self.mapping:
                    self.mapping[domain] = f"unknown{self.counter}.test"
                    self.counter += 1
                    changed = True
                    logger.info(f"[UNKNOWN] Domain anonymized: {domain} -> {self.mapping[domain]}")
                
                anon_url = full_url.replace(domain, self.mapping[domain])
                text = text.replace(full_url, anon_url)
        
        # Tokens/API Keys
        for match in re.finditer(r'\b([A-Za-z0-9]{32,})\b', text):
            token = match.group(1)
            
            if not token.isdigit() and token not in self.mapping:
                self.mapping[token] = f"TOKEN_{self.counter}"
                self.counter += 1
                changed = True
                logger.info(f"[TOKEN] Anonymized (hash): {hash(token) % 10000}")
            
            if token in self.mapping:
                text = text.replace(token, self.mapping[token])
        
        # Database names
        for match in re.finditer(r'\b([a-z_][a-z0-9_]{3,})\s*\.\s*([a-z_][a-z0-9_]+)', text, re.I):
            db, table = match.groups()
            skip_dbs = ['information_schema', 'mysql', 'performance_schema', 'sys']
            
            for item in [db, table]:
                if item.lower() not in skip_dbs and item not in self.mapping:
                    self.mapping[item] = f"db_{self.counter}"
                    self.counter += 1
                    changed = True
                    logger.info(f"[DATABASE] Anonymized: {item} -> {self.mapping[item]}")
        
        # IPs (tylko publiczne)
        for match in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
            ip = match.group(1)
            
            if self._is_whitelisted(ip) or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                continue
            
            if ip not in self.mapping:
                self.mapping[ip] = f"10.0.{self.counter // 255}.{self.counter % 255}"
                self.counter += 1
                changed = True
                logger.info(f"[IP] Public IP anonymized: {ip} -> {self.mapping[ip]}")
            
            text = text.replace(ip, self.mapping[ip])
        
        # Apply all remaining replacements
        for original, anon in self.mapping.items():
            if not self._is_whitelisted(original):
                text = text.replace(original, anon)
        
        # Save if changed
        if changed:
            self._save_mapping()
        
        # Log summary
        if text != original_text:
            logger.warning("="*80)
            logger.warning("[ANONYMIZE] TEXT ANONYMIZED:")
            logger.warning(f"   BEFORE: {original_text[:150]}...")
            logger.warning(f"   AFTER:  {text[:150]}...")
            logger.warning("="*80)
        
        return text
    
    def deanonymize(self, text: str) -> str:
        """Przywraca oryginalne wartosci"""
        if not isinstance(text, str):
            return text
        
        # Reverse mapping
        for original, anonymized in self.mapping.items():
            text = text.replace(anonymized, original)
        
        return text
    
    def anonymize_dict(self, data: Dict) -> Dict:
        """Anonimizuje dictionary rekurencyjnie"""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.anonymize(value)
            elif isinstance(value, dict):
                result[key] = self.anonymize_dict(value)
            elif isinstance(value, list):
                result[key] = [self.anonymize(v) if isinstance(v, str) else v for v in value]
            else:
                result[key] = value
        return result
    
    def deanonymize_dict(self, data: Dict) -> Dict:
        """De-anonimizuje dictionary rekurencyjnie"""
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.deanonymize(value)
            elif isinstance(value, dict):
                result[key] = self.deanonymize_dict(value)
            elif isinstance(value, list):
                result[key] = [self.deanonymize(v) if isinstance(v, str) else v for v in value]
            else:
                result[key] = value
        return result


class HexStrikeMCPBridge:
    """MCP Bridge do HexStrike API"""
    
    def __init__(self, hexstrike_url: str = "http://127.0.0.1:8888"):
        self.hexstrike_url = hexstrike_url
        self.anon = SecureAnonymizationEngine()
        
    def handle_mcp_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Obsluguje MCP request od AI Assistant"""
        
        method = request.get("method")
        params = request.get("params", {})
        
        if method == "tools/list":
            return self.list_tools()
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            return self.call_tool(tool_name, tool_args)
        else:
            return {"error": f"Unknown method: {method}"}
    
    def list_tools(self) -> Dict[str, Any]:
        """Lista dostepnych narzedzi"""
        
        tools = [
            {
                "name": "hexstrike_sqlmap",
                "description": "Advanced SQL injection testing with AWS WAF bypass techniques. Supports custom payloads, tamper scripts, and Laravel-specific attacks.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "data": {"type": "string", "description": "POST data (optional)"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                        "param": {"type": "string", "description": "Parameter to test"},
                        "level": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1},
                        "risk": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1},
                        "tamper": {"type": "string", "description": "Tamper scripts"},
                        "technique": {"type": "string", "description": "SQL injection technique"},
                        "headers": {"type": "object", "description": "Custom headers"}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "hexstrike_nmap",
                "description": "Network port scanning",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "ports": {"type": "string"}
                    },
                    "required": ["target"]
                }
            }
        ]
        
        return {"tools": tools}
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Wywoluje narzedzie HexStrike"""
        
        logger.info("="*80)
        logger.info(f"[TOOL CALL] {tool_name}")
        logger.info(f"[FROM AI] Anonymized arguments:")
        logger.info(json.dumps(arguments, indent=2))
        
        # DE-ANONIMIZACJA przed wyslaniem do HexStrike!
        real_arguments = self.anon.deanonymize_dict(arguments)
        
        logger.warning("="*80)
        logger.warning("[DEANONYMIZE] FOR HEXSTRIKE:")
        logger.warning(f"REAL arguments (sent to HexStrike):")
        logger.warning(json.dumps(real_arguments, indent=2))
        logger.warning("="*80)
        
        # Mapowanie tool names
        tool_mapping = {
            "hexstrike_sqlmap": "sqlmap",
            "hexstrike_nmap": "nmap",
            "hexstrike_nikto": "nikto"
        }
        
        hexstrike_tool = tool_mapping.get(tool_name, tool_name.replace("hexstrike_", ""))
        
        # Wywolaj HexStrike API
        try:
            url = f"{self.hexstrike_url}/api/tools/{hexstrike_tool}"
            
            logger.info(f"[CALL] HexStrike: POST {url}")
            
            response = requests.post(url, json=real_arguments, timeout=120)
            result = response.json()
            
            logger.info(f"[RESPONSE] HexStrike: {response.status_code}")
            logger.debug(f"Raw result: {json.dumps(result, indent=2)[:2000]}")
            
            # ANONIMIZACJA wyniku przed wyslaniem do AI Assistant!
            anon_result = self.anon.anonymize_dict(result)
            
            logger.warning("="*80)
            logger.warning("[REANONYMIZE] FOR AI:")
            logger.warning(f"Anonymized result (sent to AI Assistant):")
            logger.warning(json.dumps(anon_result, indent=2)[:1000])
            logger.warning("="*80)
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(anon_result, indent=2)
                    }
                ]
            }
            
        except Exception as e:
            logger.error(f"[ERROR] HexStrike call failed: {e}", exc_info=True)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error calling HexStrike: {str(e)}"
                    }
                ],
                "isError": True
            }


def main():
    """Main MCP stdio loop"""
    
    bridge = HexStrikeMCPBridge()
    
    logger.info("="*80)
    logger.info("MCP BRIDGE SESSION START")
    logger.info(f"Log file: {log_file}")
    logger.info(f"Mapping file: {MAPPING_FILE}")
    logger.info(f"Real targets file: {REAL_TARGETS_FILE}")
    logger.info("MCP Client CANNOT read sensitive mappings!")
    logger.info("="*80)
    
    # MCP stdio protocol
    for line in sys.stdin:
        try:
            request = json.loads(line)
            
            # LOG: RAW request od AI Assistant
            logger.info("="*80)
            logger.info("[INCOMING] FROM AI (before anonymization):")
            logger.info(json.dumps(request, indent=2))
            logger.info("="*80)
            
            # Anonimizuj incoming request
            if "params" in request and "arguments" in request["params"]:
                original_args = request["params"]["arguments"].copy()
                request["params"]["arguments"] = bridge.anon.anonymize_dict(request["params"]["arguments"])
                
                # LOG: Co zostalo zanonimizowane
                logger.warning("[ANONYMIZE] APPLIED:")
                logger.warning(f"BEFORE: {json.dumps(original_args, indent=2)}")
                logger.warning(f"AFTER:  {json.dumps(request['params']['arguments'], indent=2)}")
            
            # Handle request
            response = bridge.handle_mcp_request(request)
            
            # LOG: Response DO AI Assistant
            logger.info("="*80)
            logger.info("[OUTGOING] TO AI (anonymized):")
            logger.info(json.dumps(response, indent=2)[:1000] + "...")
            logger.info("="*80)
            
            # Wyslij response
            print(json.dumps(response))
            sys.stdout.flush()
            
        except Exception as e:
            logger.error(f"[ERROR] Request handling failed: {e}", exc_info=True)
            error_response = {
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            }
            print(json.dumps(error_response))
            sys.stdout.flush()


if __name__ == "__main__":
    main()

