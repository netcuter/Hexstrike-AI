#!/usr/bin/env python3
"""
Hexstrike 7 PL - Guardrails Layer
Scope enforcement, blast-radius control, per-target rate limiting, kill-switch, audit trail

Features:
- ScopeValidator     — validates targets against session scope (CIDR, hostname, regex, wildcard)
- BlastRadiusTier    — safe / intrusive / destructive tool classification
- TargetRateLimiter  — per-hostname/IP concurrency and req/s limits
- KillSwitch         — instant process termination per session
- AuditLogger        — full audit trail per session (→ session DB → report)
- register_guardrails(app) — Flask integration

API Endpoints:
  POST /api/guardrails/validate          — validate target against active session scope
  POST /api/session/<id>/kill            — kill all processes for session
  GET  /api/session/<id>/audit           — get audit log for session
  GET  /api/guardrails/tiers             — blast-radius tier classification
"""

import ipaddress
import re
import sqlite3
import time
import threading
import os
import signal
import fnmatch
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from flask import Flask, request, jsonify
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("HEXSTRIKE_SESSION_DB", "hexstrike_sessions.db")

# ============================================================================
# BLAST-RADIUS TIER CLASSIFICATION
# ============================================================================

class BlastRadius(str, Enum):
    SAFE        = "safe"         # passive recon, no traffic to target
    INTRUSIVE   = "intrusive"    # active scanning, moderate noise
    DESTRUCTIVE = "destructive"  # exploitation, brute force, DoS-risk

# Tool → tier mapping  (lowercase keys)
TOOL_TIERS: Dict[str, BlastRadius] = {
    # SAFE
    "whois":        BlastRadius.SAFE,
    "dig":          BlastRadius.SAFE,
    "host":         BlastRadius.SAFE,
    "subfinder":    BlastRadius.SAFE,
    "amass":        BlastRadius.SAFE,
    "theHarvester": BlastRadius.SAFE,
    "shodan":       BlastRadius.SAFE,
    "censys":       BlastRadius.SAFE,
    "crtsh":        BlastRadius.SAFE,
    "waybackurls":  BlastRadius.SAFE,
    "dnsrecon":     BlastRadius.SAFE,
    # INTRUSIVE
    "nmap":         BlastRadius.INTRUSIVE,
    "masscan":      BlastRadius.INTRUSIVE,
    "nikto":        BlastRadius.INTRUSIVE,
    "gobuster":     BlastRadius.INTRUSIVE,
    "dirb":         BlastRadius.INTRUSIVE,
    "feroxbuster":  BlastRadius.INTRUSIVE,
    "ffuf":         BlastRadius.INTRUSIVE,
    "wpscan":       BlastRadius.INTRUSIVE,
    "nuclei":       BlastRadius.INTRUSIVE,
    "testssl":      BlastRadius.INTRUSIVE,
    "sslscan":      BlastRadius.INTRUSIVE,
    "curl":         BlastRadius.INTRUSIVE,
    "whatweb":      BlastRadius.INTRUSIVE,
    # DESTRUCTIVE
    "sqlmap":       BlastRadius.DESTRUCTIVE,
    "hydra":        BlastRadius.DESTRUCTIVE,
    "medusa":       BlastRadius.DESTRUCTIVE,
    "metasploit":   BlastRadius.DESTRUCTIVE,
    "msfconsole":   BlastRadius.DESTRUCTIVE,
    "burpsuite":    BlastRadius.DESTRUCTIVE,
    "john":         BlastRadius.DESTRUCTIVE,
    "hashcat":      BlastRadius.DESTRUCTIVE,
    "beef":         BlastRadius.DESTRUCTIVE,
    "setoolkit":    BlastRadius.DESTRUCTIVE,
}


def classify_tool(tool_name: str, command: str = "") -> BlastRadius:
    """Classify a tool/command into blast-radius tier"""
    name_lower = (tool_name or "").lower().split()[0]
    if name_lower in TOOL_TIERS:
        return TOOL_TIERS[name_lower]
    # Fallback: scan command tokens for known tool names
    for token in (command or "").lower().split():
        if token in TOOL_TIERS:
            return TOOL_TIERS[token]
    # Default: intrusive for unknown tools (conservative)
    return BlastRadius.INTRUSIVE


# ============================================================================
# SCOPE VALIDATOR
# ============================================================================

class ScopeValidator:
    """
    Validates targets against session scope rules.
    Scope stored as newline-separated entries in session.scope field:
      - CIDR:    192.168.1.0/24
      - hostname: example.com
      - wildcard: *.example.com
      - regex (prefixed r:): r:.*\\.internal\\.corp$
    """

    @staticmethod
    def parse_scope(scope_str: str) -> List[str]:
        if not scope_str:
            return []
        return [s.strip() for s in scope_str.splitlines() if s.strip()]

    @staticmethod
    def normalize_target(target: str) -> str:
        """Strip protocol, path, port from target to get hostname/IP"""
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0]   # remove path
        target = target.split(':')[0]   # remove port
        return target.strip().lower()

    @classmethod
    def is_in_scope(cls, target: str, scope_str: str) -> Tuple[bool, str]:
        """
        Returns (in_scope, matched_rule_or_reason)
        Empty scope → ALLOW (no restrictions set)
        """
        rules = cls.parse_scope(scope_str)
        if not rules:
            return True, "no_scope_defined"

        normalized = cls.normalize_target(target)

        for rule in rules:
            # CIDR check
            try:
                network = ipaddress.ip_network(rule, strict=False)
                target_ip = ipaddress.ip_address(normalized)
                if target_ip in network:
                    return True, f"cidr:{rule}"
            except ValueError:
                pass  # not a CIDR, try next

            # Regex rule (prefix r:)
            if rule.startswith("r:"):
                pattern = rule[2:]
                try:
                    if re.match(pattern, normalized):
                        return True, f"regex:{rule}"
                except re.error:
                    pass

            # Wildcard / fnmatch (e.g. *.example.com)
            if fnmatch.fnmatch(normalized, rule.lower()):
                return True, f"wildcard:{rule}"

            # Exact hostname match
            if normalized == rule.lower():
                return True, f"exact:{rule}"

        return False, f"out_of_scope: '{normalized}' not in {rules}"


# ============================================================================
# PER-TARGET RATE LIMITER
# ============================================================================

class TargetRateLimiter:
    """
    Per-hostname/IP rate limiter — protects target systems from being overwhelmed.
    Default: max 5 concurrent requests per target, max 10 req/s per target.
    """

    def __init__(self, max_concurrent: int = 5, max_per_second: int = 10):
        self.max_concurrent = max_concurrent
        self.max_per_second = max_per_second
        self._semaphores: Dict[str, threading.Semaphore] = {}
        self._timestamps: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def _get_semaphore(self, target: str) -> threading.Semaphore:
        with self._lock:
            if target not in self._semaphores:
                self._semaphores[target] = threading.Semaphore(self.max_concurrent)
            return self._semaphores[target]

    def check_rate(self, target: str) -> Tuple[bool, str]:
        """Check req/s rate for target (non-blocking)"""
        now = time.time()
        with self._lock:
            ts = self._timestamps.get(target, [])
            ts = [t for t in ts if now - t < 1.0]  # sliding 1-second window
            if len(ts) >= self.max_per_second:
                return False, f"Target rate limit: max {self.max_per_second} req/s for {target}"
            ts.append(now)
            self._timestamps[target] = ts
        return True, "ok"

    def acquire(self, target: str) -> bool:
        """Try to acquire concurrency slot (non-blocking)"""
        sem = self._get_semaphore(target)
        return sem.acquire(blocking=False)

    def release(self, target: str):
        """Release concurrency slot"""
        sem = self._get_semaphore(target)
        sem.release()


# ============================================================================
# KILL SWITCH
# ============================================================================

class KillSwitch:
    """Track and terminate all subprocesses per session"""

    def __init__(self):
        self._session_pids: Dict[str, Set[int]] = {}
        self._lock = threading.Lock()

    def register_pid(self, session_id: str, pid: int):
        with self._lock:
            if session_id not in self._session_pids:
                self._session_pids[session_id] = set()
            self._session_pids[session_id].add(pid)

    def kill_session(self, session_id: str) -> Dict:
        """Kill all processes for a session. Returns summary."""
        with self._lock:
            pids = list(self._session_pids.get(session_id, set()))

        killed = []
        failed = []
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                killed.append(pid)
            except ProcessLookupError:
                killed.append(pid)  # already gone
            except PermissionError:
                failed.append(pid)
            except Exception as e:
                failed.append(pid)
                logger.warning(f"Kill PID {pid}: {e}")

        with self._lock:
            self._session_pids.pop(session_id, None)

        return {"killed": killed, "failed": failed, "total": len(pids)}

    def cleanup_pid(self, session_id: str, pid: int):
        with self._lock:
            if session_id in self._session_pids:
                self._session_pids[session_id].discard(pid)


# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """Append-only audit trail per session, persisted to SQLite"""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_table()

    def _init_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ts        TEXT NOT NULL,
                event     TEXT NOT NULL,
                tool      TEXT,
                target    TEXT,
                tier      TEXT,
                result    TEXT,
                detail    TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log(self, session_id: str, event: str, tool: str = None,
            target: str = None, tier: str = None, result: str = None,
            detail: str = None):
        ts = datetime.utcnow().isoformat() + "Z"
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO audit_log (session_id,ts,event,tool,target,tier,result,detail) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (session_id, ts, event, tool, target, tier, result, detail)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"AuditLogger write failed: {e}")

    def get_log(self, session_id: str) -> List[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE session_id=? ORDER BY ts",
                (session_id,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"AuditLogger read failed: {e}")
            return []

    def get_methodology_section(self, session_id: str) -> str:
        """Generate Methodology markdown section for pentest report"""
        entries = self.get_log(session_id)
        if not entries:
            return ""

        lines = ["## Methodology & Audit Trail\n",
                 "| Timestamp | Event | Tool | Target | Tier | Result |",
                 "|-----------|-------|------|--------|------|--------|"]
        for e in entries:
            lines.append(
                f"| {e['ts']} | {e['event']} | {e.get('tool') or '-'} "
                f"| {e.get('target') or '-'} | {e.get('tier') or '-'} "
                f"| {e.get('result') or '-'} |"
            )
        violations = [e['event'] for e in entries if e.get('result') == 'BLOCKED']
        if violations:
            kinds = sorted(set(violations))
            lines.append(f"\n> ⚠️ Guardrail blocks detected ({', '.join(kinds)}) — see BLOCKED entries above.")
        return "\n".join(lines)


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

scope_validator    = ScopeValidator()
target_rate_limiter = TargetRateLimiter(
    max_concurrent=int(os.environ.get("HEXSTRIKE_TARGET_MAX_CONCURRENT", "5")),
    max_per_second=int(os.environ.get("HEXSTRIKE_TARGET_MAX_RPS", "10")),
)
kill_switch  = KillSwitch()
audit_logger = AuditLogger()

GUARDRAILS_ENABLED = os.environ.get("HEXSTRIKE_GUARDRAILS", "true").lower() == "true"


# ============================================================================
# HELPER: get active session scope from DB
# ============================================================================

def _get_session_scope(session_id: str) -> Optional[str]:
    """Look up scope string for a session"""
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT scope FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def validate_target_against_session(session_id: str, target: str, tool: str = None,
                                    command: str = None) -> Tuple[bool, str, str]:
    """
    Full guardrail check: scope + tier.
    Returns (allowed, reason, tier)
    """
    if not GUARDRAILS_ENABLED:
        return True, "guardrails_disabled", "unknown"

    scope_str = _get_session_scope(session_id)
    in_scope, scope_reason = scope_validator.is_in_scope(target, scope_str or "")
    tier = classify_tool(tool or "", command or "").value

    if not in_scope:
        audit_logger.log(
            session_id=session_id, event="scope_violation",
            tool=tool, target=target, tier=tier,
            result="BLOCKED", detail=scope_reason
        )
        return False, scope_reason, tier

    audit_logger.log(
        session_id=session_id, event="tool_call",
        tool=tool, target=target, tier=tier,
        result="ALLOWED", detail=scope_reason
    )
    return True, scope_reason, tier


# ============================================================================
# FLASK REGISTRATION
# ============================================================================

def register_guardrails(app: Flask):
    """Register guardrail endpoints and middleware on Flask app"""

    @app.route("/api/guardrails/validate", methods=["POST"])
    def guardrails_validate():
        """
        Validate a target + tool against an active session scope.

        Body: { "session_id": "...", "target": "...", "tool": "...", "command": "..." }
        Returns: { "allowed": bool, "tier": str, "reason": str }
        """
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        target     = data.get("target", "")
        tool       = data.get("tool", "")
        command    = data.get("command", "")

        if not session_id or not target:
            return jsonify({"error": "session_id and target required"}), 400

        allowed, reason, tier = validate_target_against_session(
            session_id, target, tool, command
        )
        return jsonify({
            "allowed": allowed,
            "tier": tier,
            "reason": reason,
            "guardrails_enabled": GUARDRAILS_ENABLED,
        })

    @app.route("/api/session/<session_id>/kill", methods=["POST"])
    def session_kill(session_id):
        """
        Kill all running processes for a session.
        Returns summary of killed PIDs.
        """
        result = kill_switch.kill_session(session_id)
        audit_logger.log(
            session_id=session_id, event="kill_switch",
            result=f"killed={len(result['killed'])} failed={len(result['failed'])}",
            detail=str(result)
        )
        return jsonify({
            "session_id": session_id,
            "kill_result": result,
            "message": f"Kill switch activated: {len(result['killed'])} processes terminated"
        })

    @app.route("/api/session/<session_id>/audit", methods=["GET"])
    def session_audit(session_id):
        """Return full audit trail for a session"""
        entries = audit_logger.get_log(session_id)
        methodology = audit_logger.get_methodology_section(session_id)
        return jsonify({
            "session_id": session_id,
            "total_events": len(entries),
            "audit_log": entries,
            "methodology_markdown": methodology,
        })

    @app.route("/api/guardrails/tiers", methods=["GET"])
    def guardrails_tiers():
        """Return blast-radius tier classification for all known tools"""
        tiers: Dict[str, List[str]] = {"safe": [], "intrusive": [], "destructive": []}
        for tool, tier in TOOL_TIERS.items():
            tiers[tier.value].append(tool)
        return jsonify({
            "tiers": tiers,
            "description": {
                "safe": "Passive recon — no intrusive traffic to target",
                "intrusive": "Active scanning — generates logs on target, use with authorization",
                "destructive": "Exploitation/brute-force — may cause downtime, requires explicit authorization",
            },
            "destructive_requires_confirmation": True,
            "confirmation_header": "X-Hexstrike-Confirm-Destructive",
        })

    logger.info("🛡️  Guardrails: ENABLED")
    logger.info("   ✅ POST /api/guardrails/validate       — scope check")
    logger.info("   ✅ POST /api/session/<id>/kill         — kill switch")
    logger.info("   ✅ GET  /api/session/<id>/audit        — audit trail")
    logger.info("   ✅ GET  /api/guardrails/tiers          — blast-radius tiers")


# ============================================================================
# DESTRUCTIVE TIER CONFIRMATION MIDDLEWARE (for external use)
# ============================================================================

def check_destructive_confirmation(tool: str, request_headers) -> Tuple[bool, str]:
    """
    For DESTRUCTIVE tier tools, require X-Hexstrike-Confirm-Destructive: yes header.
    Returns (confirmed, error_message)
    """
    tier = classify_tool(tool)
    if tier != BlastRadius.DESTRUCTIVE:
        return True, ""
    confirm = request_headers.get("X-Hexstrike-Confirm-Destructive", "").lower()
    if confirm == "yes":
        return True, ""
    return False, (
        f"Tool '{tool}' is DESTRUCTIVE tier. "
        "Add header: X-Hexstrike-Confirm-Destructive: yes to confirm intentional use."
    )
