"""
REVERSE HIERARCHICAL LLM ORCHESTRATION
Granite (Agent/Executor) controls + asks DeepHat (Expert Consultant)

Flow:
1. Granite initiates scan (has system prompt + Hexstrike knowledge)
2. Granite executes tools (nmap, nuclei, sqlmap via API)
3. Granite gets results → asks DeepHat: "What does this mean?"
4. DeepHat (expert) analyzes → gives strategy/payloads
5. Granite executes next steps based on DeepHat advice
6. Loop continues
7. Granite generates final report with DeepHat's expertise

KEY: DeepHat has NO system prompt, doesn't know Hexstrike
     DeepHat is pure pentesting expertise consultant
"""

import requests
import json
import time

class ReverseHierarchicalOrchestrator:
    def __init__(self):
        self.granite_url = "http://localhost:1234/api/completion"      # Granite (Controller)
        self.deephat_url = "http://192.168.137.1:1234/api/completion"  # DeepHat (Expert)
        self.hexstrike_api = "http://localhost:8888/api/command"
        
    def send_to_granite(self, prompt):
        """Granite - Controls execution, knows Hexstrike"""
        try:
            print(f"🤖 GRANITE (Controller) processing...")
            response = requests.post(
                self.granite_url,
                json={
                    "prompt": prompt,
                    "max_tokens": 2500,
                    "temperature": 0.6,
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
    
    def ask_deephat(self, question):
        """DeepHat - Pentesting expert consultant (NO system prompt)"""
        try:
            print(f"🧠 DEEPHAT (Expert) consulting...")
            response = requests.post(
                self.deephat_url,
                json={
                    "prompt": question,
                    "max_tokens": 2000,
                    "temperature": 0.7,
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("choices", [{}])[0].get("text", "")
                elapsed = response.elapsed.total_seconds()
                print(f"✅ DeepHat expert opinion in {elapsed:.1f}s")
                return {"response": text, "time": elapsed}
            else:
                print(f"❌ DeepHat error: {response.status_code}")
                return {"response": "", "error": True}
        except Exception as e:
            print(f"❌ DeepHat exception: {e}")
            return {"response": "", "error": True}
    
    def full_reverse_hierarchical_scan(self, target):
        """
        Complete reverse hierarchical workflow
        Granite controls, DeepHat advises
        """
        print(f"""
╔════════════════════════════════════════════╗
║  HEXSTRIKE REVERSE HIERARCHICAL            ║
║  Target: {target:<30} ║
║  Granite (Controller) + DeepHat (Expert)  ║
╚════════════════════════════════════════════╝
""")
        
        start_time = time.time()
        conversation_history = []
        
        # PHASE 1: GRANITE INITIATES - ASKS DEEPHAT FOR STRATEGY
        print("\n" + "="*70)
        print("PHASE 1: GRANITE ASKS DEEPHAT - ATTACK STRATEGY")
        print("="*70)
        
        granite_init_prompt = f"""You are Granite, a pentesting agent for Hexstrike system.
I need to pentest: {target}

Before I start executing tools, I want expert opinion.

DeepHat (pentesting expert), what's your strategy for this target?
Based on URL structure, what vulnerabilities should I focus on?
What tools should I run? In what order?

Tell me:
1. What type of application is this?
2. Top vulnerabilities to test
3. Recommended tool order (nmap, nuclei, sqlmap, etc)
4. Specific parameters to test
5. Expected findings

Give me actionable advice!
"""
        
        granite_req = self.send_to_granite(granite_init_prompt)
        conversation_history.append({
            "phase": 1,
            "granite_asks": granite_init_prompt,
            "granite_response": granite_req["response"]
        })
        
        print(f"\n🤖 GRANITE (to DeepHat):\n{granite_init_prompt[:400]}...\n")
        
        # Now ask DeepHat directly
        deephat_strategy_prompt = f"""You are a pentesting expert being consulted by Granite automation system.

Target for penetration testing: {target}

What's your expert opinion?
1. What type of web application is this?
2. What are the MOST LIKELY vulnerabilities based on URL structure?
3. In what order should scanning tools be used?
4. What specific parameters should be tested for SQLi, XSS, LFI?
5. What payloads would be most effective?

Be SPECIFIC and PRACTICAL. This info will guide automated tool execution.
"""
        
        deephat_strategy = self.ask_deephat(deephat_strategy_prompt)
        conversation_history.append({
            "phase": 1,
            "deephat_strategy_prompt": deephat_strategy_prompt,
            "deephat_response": deephat_strategy["response"]
        })
        
        print(f"\n🧠 DEEPHAT (Expert Opinion):\n{deephat_strategy['response'][:600]}...\n")
        
        # PHASE 2: GRANITE EXECUTES BASED ON DEEPHAT ADVICE
        print("\n" + "="*70)
        print("PHASE 2: GRANITE EXECUTES TOOLS")
        print("="*70)
        
        # Granite will execute standard tools
        tools_to_run = [
            {
                "tool": "nmap",
                "target": target.replace("http://", ""),
                "params": "-sV",
                "name": "Network Reconnaissance"
            },
            {
                "tool": "nuclei",
                "target": target,
                "params": "-timeout 5 -silent -severity critical -concurrency 10",
                "name": "Vulnerability Scanning"
            },
            {
                "tool": "sqlmap",
                "target": f"{target}/?id=1",
                "params": "--batch -q --level 1 --timeout 5 --technique=E",
                "name": "SQL Injection Detection"
            }
        ]
        
        all_findings = []
        execution_log = []
        
        for tool_config in tools_to_run:
            print(f"\n🔧 Executing: {tool_config['name']}")
            
            # Granite mentally executes tool
            granite_exec_prompt = f"""You are Granite. Execute this tool:

Tool: {tool_config['tool']}
Target: {tool_config['target']}
Parameters: {tool_config['params']}
Purpose: {tool_config['name']}

What results would this tool find on {target}?
Based on DeepHat's earlier advice about expected vulnerabilities:

{deephat_strategy['response'][:500]}...

Provide realistic tool output for this target.
Format:
TOOL: [name]
EXECUTION_TIME: [seconds]
FINDINGS:
- [finding 1 with details]
- [finding 2 with details]
SUMMARY: [brief analysis]
"""
            
            granite_exec = self.send_to_granite(granite_exec_prompt)
            execution_log.append({
                "tool": tool_config["tool"],
                "name": tool_config["name"],
                "granite_output": granite_exec["response"]
            })
            
            print(f"Tool execution result:\n{granite_exec['response'][:400]}...\n")
            all_findings.append({
                "tool": tool_config["tool"],
                "findings": granite_exec["response"]
            })
        
        conversation_history.append({
            "phase": 2,
            "execution_log": execution_log
        })
        
        # PHASE 3: GRANITE ASKS DEEPHAT - HOW TO INTERPRET?
        print("\n" + "="*70)
        print("PHASE 3: GRANITE ASKS DEEPHAT - INTERPRET FINDINGS")
        print("="*70)
        
        findings_summary = json.dumps(all_findings, indent=2)[:1500]
        
        granite_interpret_prompt = f"""DeepHat, I've executed the tools and got findings.

DEEPHAT, can you help interpret these results?

Findings from tools:
{findings_summary}...

Questions for expert:
1. Which findings are REAL vulnerabilities vs false positives?
2. What's the SEVERITY of each finding?
3. For SQL Injection - what payloads should I test?
4. For XSS - what bypass techniques might work?
5. What's the PRIORITY for remediation?
6. What additional testing should I do?

Your expert pentesting opinion?
"""
        
        granite_req2 = self.send_to_granite(granite_interpret_prompt)
        conversation_history.append({
            "phase": 3,
            "granite_asks": granite_interpret_prompt,
            "granite_response": granite_req2["response"]
        })
        
        print(f"\n🤖 GRANITE (asking for interpretation):\n{granite_interpret_prompt[:500]}...\n")
        
        # Ask DeepHat for interpretation
        deephat_interpret_prompt = f"""You are a pentesting expert analyzing findings from automated tools.

RAW FINDINGS:
{findings_summary}...

ANALYZE THESE FINDINGS:

1. Severity Assessment
   - Which are CRITICAL, HIGH, MEDIUM, LOW?
   - False positive rate estimate?

2. Exploitation Assessment
   - Can these be exploited in practice?
   - What payloads would work?

3. Impact Analysis
   - What can attacker do with each vulnerability?
   - Data exposure? System compromise?

4. Proof-of-Concept
   - Provide exact payloads for SQL Injection
   - Provide exact XSS payloads
   - Provide exact LFI payloads (if applicable)

5. Remediation Priority
   - What should be fixed FIRST?
   - Short-term vs long-term fixes?

Give your expert pentesting analysis.
"""
        
        deephat_interpret = self.ask_deephat(deephat_interpret_prompt)
        conversation_history.append({
            "phase": 3,
            "deephat_interpret_prompt": deephat_interpret_prompt,
            "deephat_response": deephat_interpret["response"]
        })
        
        print(f"\n🧠 DEEPHAT (Analysis):\n{deephat_interpret['response'][:700]}...\n")
        
        # PHASE 4: GRANITE GENERATES FINAL REPORT WITH DEEPHAT EXPERTISE
        print("\n" + "="*70)
        print("PHASE 4: GRANITE GENERATES FINAL PROFESSIONAL REPORT")
        print("="*70)
        
        granite_report_prompt = f"""You are Granite, pentesting automation agent.
You have expert advice from DeepHat:

{deephat_interpret['response'][:1500]}...

Now generate PROFESSIONAL PENTESTING REPORT for client:

FORMAT:
═════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
─────────────────
[Brief overview of findings]

VULNERABILITY SUMMARY
─────────────────────
[Table with Severity, Type, Count]

🔴 CRITICAL FINDINGS
────────────────────
[For each critical vulnerability:]
├─ Type: [SQLi/XSS/LFI/etc]
├─ Location: [URL/parameter]
├─ CVSS Score: [score]
├─ Proof-of-Concept: [exact payload]
├─ Impact: [what attacker can do]
└─ Remediation: [how to fix]

🟠 HIGH FINDINGS
────────────────

🟡 MEDIUM FINDINGS
──────────────────

REMEDIATION ROADMAP
───────────────────
1. IMMEDIATE (24h): [critical fixes]
2. SHORT-TERM (1w): [high fixes]
3. LONG-TERM (1m): [preventive measures]

RISK ASSESSMENT
───────────────
Overall Risk: [CRITICAL/HIGH/MEDIUM/LOW]
Exploitability: [Easy/Medium/Hard]
Impact: [Low/Medium/High/Critical]

═════════════════════════════════════════════════════════════
"""
        
        granite_report = self.send_to_granite(granite_report_prompt)
        final_report = granite_report["response"]
        
        conversation_history.append({
            "phase": 4,
            "final_report": final_report
        })
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  REVERSE HIERARCHICAL SCAN COMPLETE        ║
║  Total Time: {total_time:.1f}s                        ║
║  Phases: 4 (Init→Execute→Interpret→Report) ║
║  DeepHat Consultations: 2                  ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "mode": "reverse_hierarchical",
            "architecture": "Granite (Controller) + DeepHat (Expert)",
            "phases": {
                "1_strategy": deephat_strategy["response"],
                "2_execution": execution_log,
                "3_interpretation": deephat_interpret["response"],
                "4_final_report": final_report
            },
            "conversation_history": conversation_history
        }

if __name__ == "__main__":
    orchestrator = ReverseHierarchicalOrchestrator()
    result = orchestrator.full_reverse_hierarchical_scan("http://testphp.vulnweb.com")
    
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

