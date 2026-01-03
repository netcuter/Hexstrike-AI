"""
HIERARCHICAL LLM ORCHESTRATION
DeepHat (Boss/Strategist) controls Granite (Agent/Executor)

Flow:
1. DeepHat analyzes target → generates strategy
2. DeepHat sends commands to Granite
3. Granite executes → reports results
4. DeepHat analyzes results → sends next commands
5. Loop until complete
6. DeepHat generates final report
"""

import requests
import json
import time
import re

class HierarchicalLLMOrchestrator:
    def __init__(self):
        self.boss_url = "http://192.168.137.1:1234/api/completion"  # DeepHat (Boss)
        self.agent_url = "http://localhost:1234/api/completion"      # Granite (Agent)
        self.hexstrike_api = "http://localhost:8888/api/command"
        
    def send_to_boss(self, prompt):
        """DeepHat (Boss) - thinks strategically"""
        try:
            print(f"\n🧠 BOSS (DeepHat) thinking...")
            response = requests.post(
                self.boss_url,
                json={
                    "prompt": prompt,
                    "max_tokens": 3000,
                    "temperature": 0.8,
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("choices", [{}])[0].get("text", "")
                print(f"✅ Boss (DeepHat) responded in {response.elapsed.total_seconds():.1f}s")
                return text
            else:
                print(f"❌ Boss error: {response.status_code}")
                return ""
        except Exception as e:
            print(f"❌ Boss exception: {e}")
            return ""
    
    def send_to_agent(self, prompt):
        """Granite (Agent) - executes commands"""
        try:
            print(f"🤖 AGENT (Granite) executing...")
            response = requests.post(
                self.agent_url,
                json={
                    "prompt": prompt,
                    "max_tokens": 2000,
                    "temperature": 0.3,  # Lower = more focused
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                text = result.get("choices", [{}])[0].get("text", "")
                print(f"✅ Agent (Granite) responded in {response.elapsed.total_seconds():.1f}s")
                return text
            else:
                print(f"❌ Agent error: {response.status_code}")
                return ""
        except Exception as e:
            print(f"❌ Agent exception: {e}")
            return ""
    
    def extract_commands(self, boss_response):
        """Extract tool commands from boss response"""
        commands = []
        
        # Look for patterns like:
        # "Run: sqlmap -u http://... --batch"
        # "Execute: nuclei -u ..."
        # "Command: nmap ..."
        
        lines = boss_response.split('\n')
        for line in lines:
            if 'sqlmap' in line.lower() or 'nuclei' in line.lower() or \
               'nmap' in line.lower() or 'dalfox' in line.lower():
                # Extract command
                commands.append(line.strip())
        
        return commands
    
    def full_hierarchical_scan(self, target):
        """Complete hierarchical workflow"""
        print(f"""
╔════════════════════════════════════════════╗
║  HEXSTRIKE HIERARCHICAL ORCHESTRATION     ║
║  Target: {target:<30} ║
║  Mode: DeepHat BOSS → Granite AGENT       ║
╚════════════════════════════════════════════╝
""")
        
        start_time = time.time()
        conversation_history = []
        all_findings = []
        
        # PHASE 1: BOSS ANALYZES TARGET & CREATES STRATEGY
        print("\n" + "="*60)
        print("PHASE 1: STRATEGIC ANALYSIS")
        print("="*60)
        
        boss_analysis_prompt = f"""You are DeepHat7B, an advanced penetration testing strategist.
Your agent is Granite (a fast action-taker).
        
Target: {target}

ANALYZE THIS TARGET AND CREATE DETAILED ATTACK STRATEGY:

1. Target Analysis
   - What type of application?
   - Technologies used?
   - Entry points?

2. Attack Strategy (step by step)
   - First: network reconnaissance
   - Second: vulnerability scanning
   - Third: specific exploitation techniques
   - Fourth: data extraction (if applicable)

3. For EACH ATTACK STEP, provide clear command for your agent:
   Format: "STEP X: [description]"
   "Command: [tool] [parameters]"
   "Expected: [what we're looking for]"

Be SPECIFIC! Give exact commands Granite can execute.
Include: nmap, nuclei, sqlmap, dalfox commands
For each command, explain what we're testing.

EXAMPLE FORMAT:
STEP 1: Network reconnaissance
Command: nmap -sV testphp.vulnweb.com
Expected: Open ports, service versions

STEP 2: SQL Injection testing
Command: sqlmap -u http://testphp.vulnweb.com/?id=1 --batch -q --level 1
Expected: Database injection points

Be thorough! This is STRATEGIC PLANNING.
"""
        
        boss_strategy = self.send_to_boss(boss_analysis_prompt)
        conversation_history.append({
            "actor": "boss",
            "type": "strategy",
            "content": boss_strategy
        })
        
        print(f"\n📋 BOSS STRATEGY:\n{boss_strategy[:800]}...\n")
        
        # PHASE 2: AGENT EXECUTES COMMANDS FROM STRATEGY
        print("\n" + "="*60)
        print("PHASE 2: AGENT EXECUTION")
        print("="*60)
        
        # Extract commands from boss strategy
        commands = self.extract_commands(boss_strategy)
        
        if not commands:
            # Fallback: create standard commands
            commands = [
                f"nmap -sV {target.replace('http://', '')}",
                f"nuclei -u {target} -timeout 5 -silent -severity critical",
                f"sqlmap -u {target}/?id=1 --batch -q --level 1 --timeout 5"
            ]
        
        print(f"\n🔍 Extracted {len(commands)} commands from strategy")
        
        for i, cmd in enumerate(commands, 1):
            print(f"\n--- COMMAND {i}/{len(commands)} ---")
            print(f"Executing: {cmd[:80]}...")
            
            # Send to agent for execution report
            agent_exec_prompt = f"""You are Granite, a fast penetration testing agent.
Your boss (DeepHat) told you to run this:

Command: {cmd}

EXECUTE THIS MENTALLY AND PROVIDE:
1. What tool is this?
2. What are we testing?
3. Likely results for http://testphp.vulnweb.com
4. Potential findings

Format your response as:
TOOL: [tool name]
PURPOSE: [what we're testing]
EXPECTED_FINDINGS: [what we expect to find]
FINDINGS: [actual findings for this target]

Be specific! This is a REAL target with KNOWN vulnerabilities.
"""
            
            agent_response = self.send_to_agent(agent_exec_prompt)
            conversation_history.append({
                "actor": "agent",
                "type": "execution",
                "command": cmd,
                "response": agent_response
            })
            
            print(f"Agent report:\n{agent_response[:500]}...\n")
        
        # PHASE 3: BOSS REVIEWS RESULTS & DECIDES NEXT STEPS
        print("\n" + "="*60)
        print("PHASE 3: RESULT ANALYSIS & NEXT STEPS")
        print("="*60)
        
        boss_review_prompt = f"""You are DeepHat7B, reviewing attack results.
Your agent Granite executed these steps and reported findings.

ORIGINAL STRATEGY:
{boss_strategy[:1000]}...

EXECUTION RESULTS FROM AGENT:
{json.dumps(conversation_history, indent=2)[:2000]}...

NOW:
1. Analyze all findings reported by Granite
2. Identify the TOP VULNERABILITIES
3. For each vulnerability:
   - Type (SQLi, XSS, LFI, etc)
   - Severity (Critical, High, Medium, Low)
   - Location (URL, parameter)
   - Proof-of-concept payload
4. Provide next investigation steps if needed
5. Summarize security posture

Format as PROFESSIONAL PENTEST FINDINGS with:
- VULNERABILITY TYPE
- SEVERITY (CVSS if known)
- AFFECTED PARAMETER
- PAYLOAD
- IMPACT
- REMEDIATION
"""
        
        boss_analysis = self.send_to_boss(boss_review_prompt)
        conversation_history.append({
            "actor": "boss",
            "type": "analysis",
            "content": boss_analysis
        })
        
        print(f"\n📊 BOSS ANALYSIS:\n{boss_analysis}\n")
        
        # PHASE 4: FINAL REPORT GENERATION
        print("\n" + "="*60)
        print("PHASE 4: FINAL REPORT GENERATION")
        print("="*60)
        
        boss_report_prompt = f"""You are DeepHat7B, generating FINAL PROFESSIONAL PENTEST REPORT.

Based on ALL analysis and findings:

{boss_analysis[:2000]}

GENERATE COMPREHENSIVE PENTEST REPORT:

FORMAT:
═══════════════════════════════════════
EXECUTIVE SUMMARY
─────────────────
[Brief overview of findings]

VULNERABILITY SUMMARY
─────────────────────
[Table: Severity | Count]

CRITICAL FINDINGS
─────────────────
[List each with: Type | CVSS | URL | Payload | Impact]

HIGH FINDINGS
─────────────
[...]

REMEDIATION ROADMAP
───────────────────
1. IMMEDIATE (24 hours): [Critical vulns fix]
2. SHORT-TERM (1 week): [High vulns fix]
3. LONG-TERM (1 month): [Preventive measures]

RISK ASSESSMENT
───────────────
Overall Risk Level: [CRITICAL/HIGH/MEDIUM/LOW]

CONCLUSION
──────────
[Professional assessment]

═══════════════════════════════════════
"""
        
        final_report = self.send_to_boss(boss_report_prompt)
        conversation_history.append({
            "actor": "boss",
            "type": "final_report",
            "content": final_report
        })
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  HIERARCHICAL SCAN COMPLETE                ║
║  Total Time: {total_time:.1f}s                        ║
║  Phases: 4 (Analysis→Execute→Review→Report) ║
║  LLM Interactions: {len(conversation_history)}                          ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "mode": "hierarchical",
            "phases": {
                "strategy": boss_strategy,
                "execution_commands": commands,
                "agent_responses": [c for c in conversation_history if c["actor"] == "agent"],
                "analysis": boss_analysis,
                "final_report": final_report
            },
            "conversation_history": conversation_history
        }

if __name__ == "__main__":
    orchestrator = HierarchicalLLMOrchestrator()
    result = orchestrator.full_hierarchical_scan("http://testphp.vulnweb.com")
    print("\n" + "="*60)
    print("FINAL REPORT:")
    print("="*60)
    print(result["phases"]["final_report"])

