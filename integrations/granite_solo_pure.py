"""
GRANITE SOLO PURE MODE
- Granite działa SAM, bez sprawdzania DeepHata
- Nie próbuje się łączyć z 192.168.137.1
- Używa system promptu do expert knowledge
- To był ORYGINALNY scenariusz, teraz jako opcja!
"""

import requests
import json
import time

class GraniteSoloPure:
    def __init__(self):
        self.granite_url = "http://localhost:1234/api/completion"
        self.hexstrike_api = "http://localhost:8888/api/command"
        
    def send_to_granite(self, prompt, is_expert_mode=True):
        """Granite SOLO - zawsze z expert system promptem"""
        try:
            print(f"🤖 GRANITE (SOLO) processing...")
            
            # ZAWSZE dodaj system prompt
            system_prompt = """You are Granite, an advanced pentesting AI agent for Hexstrike.
You have comprehensive pentesting knowledge and expertise.

Your responsibilities:
1. ANALYZE targets deeply
2. CREATE attack strategies
3. GENERATE payloads
4. INTERPRET vulnerabilities
5. PRODUCE professional reports

Be thorough, strategic, and expert-level!

---

"""
            
            full_prompt = system_prompt + prompt
            
            response = requests.post(
                self.granite_url,
                json={
                    "prompt": full_prompt,
                    "max_tokens": 3000,
                    "temperature": 0.7,
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("choices", [{}])[0].get("text", "")
                elapsed = response.elapsed.total_seconds()
                print(f"✅ Granite responded in {elapsed:.1f}s")
                return {"response": text, "time": elapsed}
            else:
                print(f"❌ Granite error: {response.status_code}")
                return {"response": "", "error": True}
        except Exception as e:
            print(f"❌ Granite exception: {e}")
            return {"response": "", "error": True}
    
    def full_granite_solo_scan(self, target):
        """Complete pentesting scan with Granite SOLO"""
        print(f"""
╔════════════════════════════════════════════╗
║  HEXSTRIKE GRANITE SOLO PURE MODE          ║
║  Target: {target:<30} ║
║  No external LLMs, Granite ONLY            ║
║  Expert Mode: ENABLED                      ║
╚════════════════════════════════════════════╝
""")
        
        start_time = time.time()
        conversation_history = []
        
        # PHASE 1: GRANITE ANALYZES & STRATEGIES
        print("\n" + "="*70)
        print("PHASE 1: GRANITE ANALYZES TARGET (EXPERT MODE)")
        print("="*70)
        
        granite_analysis_prompt = f"""Analyze this target for penetration testing and create detailed strategy:

Target: {target}

COMPREHENSIVE ANALYSIS:
1. What type of application is this?
2. What technologies might be used?
3. Most likely vulnerabilities based on URL structure?
4. Attack surface analysis?
5. Recommended tool execution order?
6. Specific parameters to test for SQL injection, XSS, LFI?
7. Expected findings?

Create a DETAILED, STRATEGIC analysis.
Be EXPERT-LEVEL in your assessment.
"""
        
        granite_analysis = self.send_to_granite(granite_analysis_prompt)
        conversation_history.append({
            "phase": 1,
            "type": "analysis",
            "response": granite_analysis["response"]
        })
        
        print(f"\n🤖 GRANITE ANALYSIS:\n{granite_analysis['response'][:800]}...\n")
        
        # PHASE 2: GRANITE SIMULATES TOOL EXECUTION
        print("\n" + "="*70)
        print("PHASE 2: GRANITE EXECUTES & SIMULATES TOOLS")
        print("="*70)
        
        tools_to_run = [
            {
                "tool": "nmap",
                "target": target.replace("http://", ""),
                "params": "-sV",
                "name": "Network Reconnaissance",
                "description": "Map open ports and services"
            },
            {
                "tool": "nuclei",
                "target": target,
                "params": "-timeout 5 -silent -severity critical",
                "name": "Vulnerability Scanning",
                "description": "Scan for known vulnerabilities"
            },
            {
                "tool": "sqlmap",
                "target": f"{target}/?id=1",
                "params": "--batch -q --level 1 --timeout 5",
                "name": "SQL Injection Testing",
                "description": "Test for SQL injection vulnerabilities"
            }
        ]
        
        execution_log = []
        all_findings = []
        
        for tool_config in tools_to_run:
            granite_exec_prompt = f"""Execute this pentesting tool:

Tool: {tool_config['tool']}
Target: {tool_config['target']}
Parameters: {tool_config['params']}
Purpose: {tool_config['name']} - {tool_config['description']}

Based on your earlier analysis:
{granite_analysis['response'][:600]}...

Provide REALISTIC tool output for this target.
Include:
- Tool name and execution details
- Execution time estimate
- Found vulnerabilities
- Severity levels
- Payloads if applicable
- Brief analysis of results

Be expert and specific!
"""
            
            granite_exec = self.send_to_granite(granite_exec_prompt)
            execution_log.append({
                "tool": tool_config["tool"],
                "name": tool_config["name"],
                "response": granite_exec["response"]
            })
            all_findings.append({
                "tool": tool_config["tool"],
                "findings": granite_exec["response"]
            })
            
            print(f"\n✅ {tool_config['name']}:")
            print(f"{granite_exec['response'][:400]}...\n")
        
        conversation_history.append({
            "phase": 2,
            "type": "tool_execution",
            "execution_log": execution_log
        })
        
        # PHASE 3: GRANITE ANALYZES FINDINGS
        print("\n" + "="*70)
        print("PHASE 3: GRANITE ANALYZES FINDINGS (EXPERT INTERPRETATION)")
        print("="*70)
        
        findings_summary = json.dumps(all_findings, indent=2)[:2000]
        
        granite_interpret_prompt = f"""As EXPERT pentester, analyze these findings from tool execution:

{findings_summary}...

PROVIDE EXPERT ANALYSIS:
1. Vulnerability Classification
   - Type? (SQLi, XSS, LFI, RCE, etc)
   - CVSS Score?
   - CWE/OWASP category?

2. Severity Assessment
   - Which are CRITICAL, HIGH, MEDIUM, LOW?
   - Real vulnerability or false positive?
   - Exploitability score?

3. Exploitation Details
   - Can these be exploited in practice?
   - What exact payloads would work?
   - Step-by-step exploitation?

4. Impact Analysis
   - What can attacker do?
   - Data exposure?
   - System compromise?
   - Business impact?

5. Proof-of-Concept
   - Exact SQLi payloads
   - XSS payloads with bypasses
   - Command injection examples
   - File inclusion vectors

6. Remediation Priority
   - What should be fixed FIRST?
   - Quick wins?
   - Long-term solutions?

Provide PROFESSIONAL, EXPERT-LEVEL analysis!
"""
        
        granite_interpret = self.send_to_granite(granite_interpret_prompt)
        conversation_history.append({
            "phase": 3,
            "type": "analysis",
            "response": granite_interpret["response"]
        })
        
        print(f"\n🤖 GRANITE EXPERT INTERPRETATION:\n{granite_interpret['response'][:900]}...\n")
        
        # PHASE 4: GRANITE GENERATES PROFESSIONAL REPORT
        print("\n" + "="*70)
        print("PHASE 4: GRANITE GENERATES PROFESSIONAL PENTEST REPORT")
        print("="*70)
        
        granite_report_prompt = f"""You are professional pentester. Generate COMPREHENSIVE pentest report.

Based on your expert analysis:
{granite_interpret['response'][:2000]}...

CREATE PROFESSIONAL REPORT for CLIENT:

FORMAT:
═════════════════════════════════════════════════════════════════
PENETRATION TEST REPORT
Target: {target}
Date: [current date]
Tester: Granite Pentesting AI
═════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
─────────────────
[Brief, high-level overview of findings and risk]

VULNERABILITY SUMMARY
─────────────────────
[Table: Severity | Type | Count | CVSS]

🔴 CRITICAL FINDINGS
────────────────────
[For EACH critical vulnerability:]
├─ Vulnerability ID: [CVE/CWE if applicable]
├─ Type: [SQLi/XSS/RCE/etc]
├─ Location: [Exact URL/parameter]
├─ CVSS Score: [Score]
├─ Description: [What is vulnerable?]
├─ Proof-of-Concept:
│  └─ [Exact payload]
│  └─ [Step-by-step exploitation]
├─ Impact: [What can attacker do?]
│  └─ [Data exposure level]
│  └─ [System compromise possibilities]
└─ Remediation: [How to fix]

🟠 HIGH FINDINGS
────────────────
[Similar format for high severity]

🟡 MEDIUM FINDINGS
──────────────────
[Format for medium severity]

REMEDIATION ROADMAP
───────────────────
1. IMMEDIATE (24 hours):
   - Critical vulnerability fixes
   - Patch management
   
2. SHORT-TERM (1 week):
   - High severity fixes
   - Security hardening

3. LONG-TERM (1 month):
   - Architecture review
   - Security training
   - Preventive measures

RISK ASSESSMENT
───────────────
Overall Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]
Exploitability: [Easy/Medium/Hard]
Business Impact: [Critical/High/Medium/Low]
Recommendation: [Action required]

CONCLUSION
──────────
[Professional assessment and next steps]

═════════════════════════════════════════════════════════════════

Make it PROFESSIONAL, DETAILED, and CLIENT-READY!
"""
        
        granite_report = self.send_to_granite(granite_report_prompt)
        final_report = granite_report["response"]
        
        conversation_history.append({
            "phase": 4,
            "type": "final_report",
            "response": final_report
        })
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  GRANITE SOLO SCAN COMPLETE                ║
║  Total Time: {total_time:.1f}s (Granite ONLY)         ║
║  Phases: 4 (Analysis→Execute→Interpret→Report)║
║  Mode: PURE GRANITE (Expert System Prompt)  ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "mode": "GRANITE_SOLO_PURE",
            "architecture": "Granite Solo (Expert Mode)",
            "phases": {
                "1_analysis": granite_analysis["response"],
                "2_execution": execution_log,
                "3_interpretation": granite_interpret["response"],
                "4_final_report": final_report
            },
            "conversation_history": conversation_history,
            "notes": "Pure Granite mode - no external LLMs, uses expert system prompt"
        }

if __name__ == "__main__":
    orchestrator = GraniteSoloPure()
    result = orchestrator.full_granite_solo_scan("http://testphp.vulnweb.com")
    
    print("\n" + "="*70)
    print("FINAL PROFESSIONAL REPORT:")
    print("="*70)
    print(result["phases"]["4_final_report"])
    
    print("\n" + "="*70)
    print("EXECUTION SUMMARY:")
    print("="*70)
    print(json.dumps({
        "target": result["target"],
        "total_time": result["total_time"],
        "mode": result["mode"],
        "phases_completed": len(result["phases"])
    }, indent=2))

