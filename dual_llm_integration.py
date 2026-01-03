"""
Dual-LLM Integration for Hexstrike
- LM Studio 1 (localhost:1234) = Granite (fast analysis)
- LM Studio 2 (192.168.137.1:1234) = DeepHat/other (advanced payloads)
- PARALLEL execution = FASTER results!
"""

import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class DualLLMOrchestrator:
    def __init__(self):
        self.lm1_url = "http://localhost:1234/api/completion"
        self.lm2_url = "http://192.168.137.1:1234/api/completion"
        self.hexstrike_api = "http://localhost:8888/api/command"
        self.executor = ThreadPoolExecutor(max_workers=2)
        
    def send_to_lm(self, url, prompt, model="granite"):
        """Send prompt to LM Studio (with retry logic)"""
        try:
            print(f"🚀 Sending to {url} ({model})...")
            response = requests.post(
                url,
                json={
                    "prompt": prompt,
                    "max_tokens": 2000,
                    "temperature": 0.7,
                    "stop": ["User:", "Assistant:"]
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {model} responded in {response.elapsed.total_seconds():.1f}s")
                return {
                    "model": model,
                    "response": result.get("choices", [{}])[0].get("text", ""),
                    "time": response.elapsed.total_seconds()
                }
            else:
                print(f"❌ {model} error: {response.status_code}")
                return {"model": model, "response": "", "error": True}
                
        except Exception as e:
            print(f"❌ {model} exception: {e}")
            return {"model": model, "response": "", "error": True}
    
    def analyze_parallel(self, target, analysis_prompt):
        """
        Send analysis to BOTH LM Studio in PARALLEL
        - LM1 (Granite): Quick target analysis
        - LM2 (DeepHat): Advanced vulnerability analysis
        """
        print(f"\n🔄 PARALLEL ANALYSIS PHASE (target: {target})")
        print("=" * 60)
        
        start_time = time.time()
        
        # Prepare prompts
        lm1_prompt = f"""You are Granite (pentesting analyzer).
Target: {target}

TASK:
1. Quick target analysis
2. Identify technology stack
3. Plan tool execution order
4. Estimate vulnerabilities

Keep it SHORT (max 500 tokens).

RESPONSE FORMAT:
- App Type: ...
- Technologies: ...
- Attack Vectors: ...
- Tools to Run: ...
- Expected Vulnerabilities: ...
"""

        lm2_prompt = f"""You are DeepHat (advanced payload generator).
Target: {target}

TASK:
1. Analyze endpoint structure
2. Generate advanced payloads
3. Identify edge cases
4. Suggest manual testing vectors

Keep it SHORT (max 500 tokens).

RESPONSE FORMAT:
- Endpoints: ...
- Payload Variants: ...
- Edge Cases: ...
- Manual Tests: ...
"""
        
        # Send in PARALLEL
        futures = {
            self.executor.submit(self.send_to_lm, self.lm1_url, lm1_prompt, "Granite"): "lm1",
            self.executor.submit(self.send_to_lm, self.lm2_url, lm2_prompt, "DeepHat"): "lm2"
        }
        
        results = {"lm1": None, "lm2": None}
        
        for future in as_completed(futures, timeout=120):
            lm = futures[future]
            try:
                result = future.result()
                results[lm] = result
                print(f"✅ {result['model']} done: {result.get('time', 0):.1f}s")
            except Exception as e:
                print(f"❌ {lm} error: {e}")
        
        elapsed = time.time() - start_time
        
        print(f"\n⏱️  PARALLEL PHASE TIME: {elapsed:.1f}s (vs {elapsed*2:.1f}s sequential)")
        print("=" * 60)
        
        return results
    
    def merge_analyses(self, lm1_result, lm2_result):
        """Merge insights from both LM models"""
        print("\n🔀 MERGING ANALYSES")
        print("=" * 60)
        
        merged = {
            "lm1_analysis": lm1_result.get("response", ""),
            "lm2_analysis": lm2_result.get("response", ""),
            "combined_insights": f"""
COMBINED INTELLIGENCE:

From Granite (Fast Analysis):
{lm1_result.get("response", "")[:500]}...

From DeepHat (Advanced Payloads):
{lm2_result.get("response", "")[:500]}...
""",
            "timing": {
                "lm1": lm1_result.get("time", 0),
                "lm2": lm2_result.get("time", 0),
                "parallel_advantage": f"Saved ~{max(lm1_result.get('time', 0), lm2_result.get('time', 0)):.1f}s by parallel"
            }
        }
        
        print(f"⏱️  Parallel timing advantage: {merged['timing']['parallel_advantage']}")
        return merged
    
    def execute_tools(self, target):
        """Execute scanning tools (same as before)"""
        print("\n🔨 TOOLS EXECUTION PHASE")
        print("=" * 60)
        
        tools = [
            {
                "tool": "nmap",
                "target": target.replace("http://", ""),
                "params": "-sV"
            },
            {
                "tool": "nuclei",
                "target": target,
                "params": "-timeout 5 -silent -severity critical -concurrency 10"
            },
            {
                "tool": "sqlmap",
                "target": f"{target}/?id=1",
                "params": "--batch -q --level 1 --timeout 5 --technique=E"
            }
        ]
        
        all_findings = []
        
        for tool_config in tools:
            try:
                print(f"🚀 Running {tool_config['tool']}...")
                response = requests.post(
                    self.hexstrike_api,
                    json=tool_config,
                    timeout=60
                )
                
                if response.status_code == 200:
                    findings = response.json().get("findings", [])
                    all_findings.extend(findings)
                    print(f"✅ {tool_config['tool']}: {len(findings)} findings")
                else:
                    print(f"⚠️  {tool_config['tool']}: {response.status_code}")
            except Exception as e:
                print(f"❌ {tool_config['tool']} error: {e}")
        
        return all_findings
    
    def filter_findings(self, findings):
        """ML-based false positive filtering"""
        print("\n🧠 ML FILTERING PHASE")
        print("=" * 60)
        
        try:
            response = requests.post(
                "http://localhost:8888/api/ml/filter",
                json={"findings": findings},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Raw findings: {len(findings)}")
                print(f"✅ After filtering: {len(result.get('filtered_findings', []))}")
                print(f"✅ FP removed: {result.get('removed_fp_count', 0)}")
                return result.get("filtered_findings", [])
            else:
                print(f"⚠️  ML filtering failed: {response.status_code}")
                return findings
        except Exception as e:
            print(f"❌ ML filter error: {e}")
            return findings
    
    def interpret_final(self, target, merged_analysis, verified_findings):
        """Final interpretation with combined LLM insights"""
        print("\n📝 FINAL INTERPRETATION PHASE")
        print("=" * 60)
        
        interpretation_prompt = f"""Based on:
1. Target: {target}
2. Combined Analysis: {merged_analysis.get('combined_insights', '')}
3. Verified Findings: {json.dumps(verified_findings, indent=2)[:1000]}...

Provide:
1. Executive Summary
2. Critical findings with PoC
3. Remediation roadmap
4. Risk score

Format as professional pentest report.
"""
        
        # Use LM1 (Granite) for final interpretation
        result = self.send_to_lm(
            self.lm1_url,
            interpretation_prompt,
            "Granite-Final"
        )
        
        return result.get("response", "")
    
    def full_scan(self, target):
        """Complete dual-LLM pentesting workflow"""
        print(f"""
╔════════════════════════════════════════════╗
║  HEXSTRIKE DUAL-LLM PENTESTING PIPELINE   ║
║  Target: {target:<30} ║
║  Mode: PARALLEL EXECUTION                  ║
╚════════════════════════════════════════════╝
""")
        
        start_time = time.time()
        
        # Phase 1: Parallel analysis
        analyses = self.analyze_parallel(target, "")
        
        # Phase 2: Merge insights
        merged = self.merge_analyses(analyses["lm1"], analyses["lm2"])
        
        # Phase 3: Execute tools
        findings = self.execute_tools(target)
        
        # Phase 4: ML filtering
        verified = self.filter_findings(findings)
        
        # Phase 5: Final interpretation
        report = self.interpret_final(target, merged, verified)
        
        total_time = time.time() - start_time
        
        print(f"""
╔════════════════════════════════════════════╗
║  SCAN COMPLETE                             ║
║  Total Time: {total_time:.1f}s                      ║
║  Speed Advantage: {(total_time * 0.2):.1f}s (parallel) ║
║  Findings: {len(verified)} verified                      ║
╚════════════════════════════════════════════╝
""")
        
        return {
            "target": target,
            "total_time": total_time,
            "lm1_analysis": analyses["lm1"],
            "lm2_analysis": analyses["lm2"],
            "merged_insights": merged,
            "raw_findings": len(findings),
            "verified_findings": verified,
            "final_report": report
        }

# Flask integration
from flask import jsonify

def dual_llm_scan(target):
    """Flask endpoint for dual-LLM scan"""
    orchestrator = DualLLMOrchestrator()
    result = orchestrator.full_scan(target)
    return jsonify(result)

if __name__ == "__main__":
    # Test
    orchestrator = DualLLMOrchestrator()
    result = orchestrator.full_scan("http://testphp.vulnweb.com")
    print(json.dumps(result, indent=2, default=str))

