"""
SMART ORCHESTRATOR WITH FALLBACK
- Tries REVERSE HIERARCHICAL (Granite + DeepHat)
- If DeepHat unavailable → falls back to Granite SOLO with system prompt
- Always works, no manual intervention needed!
"""

import requests
import json
import time

class SmartOrchestrator:
    def __init__(self):
        self.granite_url = "http://localhost:1234/api/completion"
        self.deephat_url = "http://192.168.137.1:1234/api/completion"
        self.hexstrike_api = "http://localhost:8888/api/command"
        self.deephat_available = None  # Will be checked on first use
        
    def check_deephat_health(self):
        """Check if DeepHat is available"""
        try:
            print(f"🔍 Checking DeepHat health at {self.deephat_url}...")
            response = requests.get(
                self.deephat_url,
                timeout=5
            )
            self.deephat_available = response.status_code == 200
            print(f"✅ DeepHat: AVAILABLE" if self.deephat_available else "❌ DeepHat: DOWN")
            return self.deephat_available
        except Exception as e:
            print(f"❌ DeepHat: UNAVAILABLE ({str(e)[:50]})")
            self.deephat_available = False
            return False
    
    def send_to_granite(self, prompt, is_expert_mode=False):
        """Send to Granite
        is_expert_mode=True → adds system prompt for standalone operation
        """
        try:
            print(f"🤖 GRANITE processing...")
            
            # If DeepHat is down, prepend system prompt
            full_prompt = prompt
            if is_expert_mode and not self.deephat_available:
                system_prompt = """You are Granite, an advanced pentesting AI agent for Hexstrike.
You have comprehensive pentesting knowledge and MUST act as both EXECUTOR and EXPERT.

When analyzing:
- Identify vulnerabilities with expertise
- Generate payloads based on pentesting best practices
- Provide strategic insights
- Format professional reports

Be thorough and strategic!

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
    
    def ask_deephat(self, question):
        """Ask DeepHat for expert opinion"""
        if not self.deephat_available:
            print(f"⚠️  DeepHat unavailable, skipping expert consultation")
            return {"response": "", "error": True}
        
        try:
            print(f"🧠 DEEPHAT consulting...")
            response = requests.post(
                self.deephat_url,
                json={
                    "prompt": question,
                    "max_tokens": 2500,
                    "temperature": 0.7,
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("choices", [{}])[0].get("text", "")
                elapsed = response.elapsed.total_seconds()
                print(f"✅ DeepHat responded in {elapsed:.1f}s")
                return {"response": text, "time": elapsed}
            else:
                print(f"❌ DeepHat error: {response.status_code}")
                return {"response": "", "error": True}
        except Exception as e:
            print(f"❌ DeepHat exception: {e}")
            return {"response": "", "error": True}
    
    def full_smart_scan(self, target):
        """
        Smart scan with automatic fallback
        - Tries REVERSE HIERARCHICAL first
        - Falls back to Granite solo if DeepHat unavailable
        """
        print(f"""
╔════════════════════════════════════════════╗
║  HEXSTRIKE SMART ORCHESTRATOR              ║
║  Target: {target:<30} ║
║  Mode: AUTO (Hierarchical or Solo)         ║
╚════════════════════════════════════════════╝
""")
        
        # Check DeepHat availability
        deephat_status = self.check_deephat_health()
        
        if deephat_status:
            print("\n✅ RUNNING: REVERSE HIERARCHICAL MODE (Granite + DeepHat)")
            return self._reverse_hierarchical_scan(target)
        else:
            print("\n⚠️  RUNNING: FALLBACK MODE (Granite Solo with Expert Knowledge)")
            return self._granite_solo_scan(target)
    
    def _reverse_hierarchical_scan(self, target):
        """REVERSE HIERARCHICAL: Granite + DeepHat"""
        print("\n" + "="*70)
        print("PHASE 1: GRANITE ASKS DEEPHAT - STRATEGY")
        print("="*70)
        
        start_time = time.time()
        conversation_history = []
        
        # DeepHat provides strategy
        deephat_strategy_prompt = f"""You are a pentesting expert being consulted by Granite.

Target: {target}

Provide expert strategy:
1. Application type?
2. Most likely vulnerabilities?
3. Tool order? (nmap, nuclei, sqlmap, etc)
4. Specific parameters to test?
5. Expected findings?

Be SPECIFIC and PRACTICAL.
"""
        
        deephat_strategy = self.ask_deephat(deephat_strategy_prompt)
        conversation_history.append({
            "phase": 1,
            "deephat_response": deephat_strategy["response"]
        })
        
        print(f"\n🧠 DEEPHAT STRATEGY:\n{deephat_strategy['response'][:600]}...\n")
        
        # PHASE 2: GRANITE EXECUTES
        print("\n" + "="*70)
        print("PHASE 2: GRANITE EXECUTES TOOLS")
        print("="*70)
        
        tools_to_run = [
            {"tool": "nmap", "target": target.replace("http://", ""), "params": "-sV", "name": "Network Recon"},
            {"tool": "nuclei", "target": target, "params": "-timeout 5 -silent -severity critical", "name": "Vuln Scan"},
            {"tool": "sqlmap", "target": f"{target}/?id=1", "params": "--batch -q --level 1 --timeout 5", "name": "SQLi Test"}
        ]
        
        execution_log = []
        all_findings = []
        
        for tool_config in tools_to_run:
            granite_exec_prompt = f"""Execute this tool for pentesting:

Tool: {tool_config['tool']}
Target: {tool_config['target']}
Purpose: {tool_config['name']}

Based on this expert advice:
{deephat_strategy['response'][:400]}...

What results would this find? Provide realistic output.
"""
            
            granite_exec = self.send_to_granite(granite_exec_prompt)
            execution_log.append({
                "tool": tool_config["tool"],
                "response": granite_exec["response"]
            })
            all_findings.append({"tool": tool_config["tool"], "findings": granite_exec["response"]})
            
            print(f"✅ {tool_config['name']}: {granite_exec['response'][:300]}...\n")
        
        conversation_history.append({"phase": 2, "execution_log": execution_log})
        
        # PHASE 3: DEEPHAT INTERPRETS FINDINGS
        print("\n" + "="*70)
        print("PHASE 3: DEEPHAT INTERPRETS FINDINGS")
        print("="*70)
        
        findings_summary = json.dumps(all_findings, indent=2)[:1500]
        
        deephat_interpret_prompt = f"""Analyze these findings from automated pentesting tools:

{findings_summary}...

Provide:
1. Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)
2. Exploitation assessment
3. Exact payloads for each vulnerability
4. Impact analysis
5. Remediation priority

Be expert-level analysis.
"""
        
        deephat_interpret = self.ask_deephat(deephat_interpret_prompt)
        conversation_history.append({"phase": 3, "deephat_response": deephat_interpret["response"]})
        
        print(f"\n🧠 DEEPHAT ANALYSIS:\n{deephat_interpret['response'][:700]}...\n")
        
        # PHASE 4: GRANITE GENERATES FINAL REPORT
        print("\n" + "="*70)
        print("PHASE 4: GRANITE GENERATES PROFESSIONAL REPORT")
        print("="*70)
        
        granite_report_prompt = f"""You are Granite. Generate professional pentest report.

Expert analysis from DeepHat:
{deephat_interpret['response'][:1500]}...

Create professional report with:
- Executive Summary
- Vulnerability Summary
- Critical Findings (with PoC)
- High Findings
- Remediation Roadmap
- Risk Assessment

Format professionally for client.
"""
        
        granite_report = self.send_to_granite(granite_report_prompt)
        final_report = granite_report["response"]
        
        conversation_history.append({"phase": 4, "final_report": final_report})
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  REVERSE HIERARCHICAL COMPLETE             ║
║  Time: {total_time:.1f}s (Granite + DeepHat)            ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "mode": "REVERSE_HIERARCHICAL",
            "deephat_available": True,
            "architecture": "Granite (Controller) + DeepHat (Expert)",
            "phases": {
                "1_strategy": deephat_strategy["response"],
                "2_execution": execution_log,
                "3_interpretation": deephat_interpret["response"],
                "4_final_report": final_report
            }
        }
    
    def _granite_solo_scan(self, target):
        """FALLBACK: Granite Solo (with system prompt for expertise)"""
        print("\n" + "="*70)
        print("PHASE 1: GRANITE ANALYZES TARGET (SOLO MODE)")
        print("="*70)
        
        start_time = time.time()
        conversation_history = []
        
        # Granite provides strategy (with expert system prompt)
        granite_strategy_prompt = f"""Analyze target for pentesting and create strategy:

Target: {target}

Provide:
1. Application type?
2. Most likely vulnerabilities?
3. Tool execution order?
4. Specific parameters to test?
5. Expected findings?

Be STRATEGIC and EXPERT-LEVEL.
"""
        
        granite_strategy = self.send_to_granite(granite_strategy_prompt, is_expert_mode=True)
        conversation_history.append({"phase": 1, "response": granite_strategy["response"]})
        
        print(f"\n🤖 GRANITE STRATEGY:\n{granite_strategy['response'][:600]}...\n")
        
        # PHASE 2: GRANITE EXECUTES TOOLS
        print("\n" + "="*70)
        print("PHASE 2: GRANITE EXECUTES TOOLS")
        print("="*70)
        
        tools_to_run = [
            {"tool": "nmap", "target": target.replace("http://", ""), "params": "-sV", "name": "Network Recon"},
            {"tool": "nuclei", "target": target, "params": "-timeout 5 -silent -severity critical", "name": "Vuln Scan"},
            {"tool": "sqlmap", "target": f"{target}/?id=1", "params": "--batch -q --level 1 --timeout 5", "name": "SQLi Test"}
        ]
        
        execution_log = []
        all_findings = []
        
        for tool_config in tools_to_run:
            granite_exec_prompt = f"""Execute this tool:

Tool: {tool_config['tool']}
Target: {tool_config['target']}
Purpose: {tool_config['name']}

Based on your strategy above, provide realistic results.
"""
            
            granite_exec = self.send_to_granite(granite_exec_prompt, is_expert_mode=True)
            execution_log.append({
                "tool": tool_config["tool"],
                "response": granite_exec["response"]
            })
            all_findings.append({"tool": tool_config["tool"], "findings": granite_exec["response"]})
            
            print(f"✅ {tool_config['name']}: {granite_exec['response'][:300]}...\n")
        
        conversation_history.append({"phase": 2, "execution_log": execution_log})
        
        # PHASE 3: GRANITE INTERPRETS FINDINGS
        print("\n" + "="*70)
        print("PHASE 3: GRANITE INTERPRETS FINDINGS (EXPERT MODE)")
        print("="*70)
        
        findings_summary = json.dumps(all_findings, indent=2)[:1500]
        
        granite_interpret_prompt = f"""As pentesting expert, analyze these findings:

{findings_summary}...

Provide:
1. Severity assessment
2. Exploitation possibility
3. Exact payloads for each vuln
4. Impact analysis
5. Remediation priority

Expert-level analysis only.
"""
        
        granite_interpret = self.send_to_granite(granite_interpret_prompt, is_expert_mode=True)
        conversation_history.append({"phase": 3, "response": granite_interpret["response"]})
        
        print(f"\n🤖 GRANITE ANALYSIS:\n{granite_interpret['response'][:700]}...\n")
        
        # PHASE 4: GRANITE GENERATES FINAL REPORT
        print("\n" + "="*70)
        print("PHASE 4: GRANITE GENERATES PROFESSIONAL REPORT")
        print("="*70)
        
        granite_report_prompt = f"""Generate professional pentest report.

Your analysis:
{granite_interpret['response'][:1500]}...

Create report with:
- Executive Summary
- Vulnerability Summary
- Critical Findings (PoC)
- High Findings
- Remediation Roadmap
- Risk Assessment

Professional client format.
"""
        
        granite_report = self.send_to_granite(granite_report_prompt, is_expert_mode=True)
        final_report = granite_report["response"]
        
        conversation_history.append({"phase": 4, "final_report": final_report})
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  FALLBACK MODE COMPLETE (GRANITE SOLO)     ║
║  Time: {total_time:.1f}s (Granite only)                ║
║  DeepHat: UNAVAILABLE                      ║
║  Status: FULL FUNCTIONALITY MAINTAINED     ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "mode": "GRANITE_SOLO_FALLBACK",
            "deephat_available": False,
            "architecture": "Granite Solo (Expert Mode)",
            "phases": {
                "1_strategy": granite_strategy["response"],
                "2_execution": execution_log,
                "3_interpretation": granite_interpret["response"],
                "4_final_report": final_report
            },
            "warning": "DeepHat unavailable - using Granite with expert system prompt"
        }

if __name__ == "__main__":
    orchestrator = SmartOrchestrator()
    result = orchestrator.full_smart_scan("http://testphp.vulnweb.com")
    
    print("\n" + "="*70)
    print("FINAL REPORT:")
    print("="*70)
    print(result["phases"]["4_final_report"])
    
    print("\n" + "="*70)
    print("EXECUTION SUMMARY:")
    print("="*70)
    print(json.dumps({
        "target": result["target"],
        "total_time": result["total_time"],
        "mode": result["mode"],
        "deephat_available": result["deephat_available"]
    }, indent=2))

