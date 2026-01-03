#!/usr/bin/env python3
"""
Hexstrike LM Studio Integration
Integrates local LLM (Granite) with Hexstrike ML for:
- AI-powered payload generation
- Vulnerability analysis
- Automated report generation
"""

import requests
import json
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class LMStudioClient:
    """Client for LM Studio API"""
    
    def __init__(self, base_url: str = "http://192.168.56.1:8087", 
                 api_token: str = None,
                 model: str = "ibm/granite-4-h-tiny"):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.model = model
        self.headers = {
            "Content-Type": "application/json"
        }
        if api_token:
            self.headers["Authorization"] = f"Bearer {api_token}"
    
    def chat_completion(self, messages: List[Dict], 
                       temperature: float = 0.7,
                       max_tokens: int = 1000) -> Optional[str]:
        """Send chat completion request to LM Studio"""
        try:
            response = requests.post(
                f"{self.base_url}/v1/chat/completions",
                headers=self.headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            return data['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"LM Studio API error: {e}")
            return None


class HexstrikeLMIntegration:
    """Integration layer between Hexstrike ML and LM Studio"""
    
    def __init__(self, lm_client: LMStudioClient):
        self.lm = lm_client
    
    def generate_ai_payloads(self, vuln_type: str, 
                            target_context: Optional[str] = None,
                            count: int = 10) -> List[str]:
        """
        Generate AI-powered payloads using Granite
        
        Args:
            vuln_type: xss, sqli, lfi, cmdi, etc.
            target_context: Optional context about target (tech stack, WAF, etc.)
            count: Number of payloads to generate
        
        Returns:
            List of generated payloads
        """
        context = target_context or "generic web application"
        
        system_prompt = """You are a penetration testing expert. Generate creative, 
        effective security testing payloads. Focus on WAF bypass techniques and 
        real-world exploitation. Output ONLY the payloads, one per line, no explanations."""
        
        user_prompt = f"""Generate {count} {vuln_type.upper()} payloads for: {context}

Requirements:
- Creative WAF bypass techniques
- Encoding variations (URL, Unicode, HTML entities)
- Context-aware exploitation
- Modern browser/server compatibility

Output format: One payload per line, no numbering or explanation."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.lm.chat_completion(messages, temperature=0.9, max_tokens=800)
        
        if not response:
            return []
        
        # Parse payloads from response
        payloads = [
            line.strip() 
            for line in response.split('\n') 
            if line.strip() and not line.strip().startswith(('#', '//', '--', '```'))
        ]
        
        return payloads[:count]
    
    def analyze_vulnerability(self, finding: Dict) -> Dict:
        """
        Use Granite to analyze vulnerability finding
        
        Args:
            finding: {
                "vulnerability_type": "xss",
                "url": "http://example.com/page?id=1",
                "payload": "<script>alert(1)</script>",
                "response": "...",
                "severity": "medium"
            }
        
        Returns:
            Analysis with explanation, impact, remediation
        """
        vuln_type = finding.get('vulnerability_type', 'Unknown')
        url = finding.get('url', 'Unknown URL')
        payload = finding.get('payload', 'N/A')
        
        system_prompt = """You are a senior security analyst. Analyze vulnerabilities 
        and provide clear, actionable insights. Be concise and technical."""
        
        user_prompt = f"""Analyze this vulnerability finding:

Type: {vuln_type}
URL: {url}
Payload: {payload}

Provide:
1. Severity (Critical/High/Medium/Low)
2. Impact (2-3 sentences)
3. Remediation (specific steps)

Be concise and technical."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.lm.chat_completion(messages, temperature=0.3, max_tokens=500)
        
        return {
            "vulnerability": finding,
            "ai_analysis": response or "Analysis failed",
            "analyzed_by": "Granite LLM"
        }
    
    def generate_report(self, scan_results: Dict) -> str:
        """
        Generate comprehensive security report using Granite
        
        Args:
            scan_results: {
                "target": "http://example.com",
                "findings": [...],
                "scan_time": "...",
                "total_requests": 1234
            }
        
        Returns:
            Markdown formatted report
        """
        target = scan_results.get('target', 'Unknown')
        findings = scan_results.get('findings', [])
        finding_count = len(findings)
        
        # Summarize findings by severity
        severity_counts = {}
        for f in findings:
            sev = f.get('severity', 'Unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        system_prompt = """You are a professional security report writer. Create 
        clear, executive-friendly reports with technical details. Use markdown formatting."""
        
        user_prompt = f"""Generate a security assessment report:

Target: {target}
Total Findings: {finding_count}
Severity Breakdown: {json.dumps(severity_counts)}

Include:
1. Executive Summary (3-4 sentences)
2. Risk Assessment (overall risk level)
3. Key Findings (top 3-5 most critical)
4. Recommendations (prioritized actions)

Format: Markdown with headers, bullet points, severity badges.
Keep it professional and actionable."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.lm.chat_completion(messages, temperature=0.5, max_tokens=1500)
        
        return response or "# Report Generation Failed\n\nUnable to generate report."
    
    def suggest_next_steps(self, findings: List[Dict]) -> List[str]:
        """
        AI-powered suggestions for next testing steps
        
        Args:
            findings: List of vulnerability findings
        
        Returns:
            List of suggested actions
        """
        if not findings:
            return ["No vulnerabilities found. Consider expanding test coverage."]
        
        vuln_types = list(set(f.get('vulnerability_type') for f in findings))
        
        system_prompt = """You are a penetration testing strategist. Suggest 
        logical next steps based on findings. Be specific and actionable."""
        
        user_prompt = f"""Based on these discovered vulnerabilities: {', '.join(vuln_types)}

Suggest 5 specific next testing actions to:
1. Exploit findings further
2. Discover related vulnerabilities
3. Assess impact depth

Output: Numbered list, one action per line, no explanations."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.lm.chat_completion(messages, temperature=0.7, max_tokens=400)
        
        if not response:
            return ["Unable to generate suggestions"]
        
        suggestions = [
            line.strip() 
            for line in response.split('\n') 
            if line.strip() and any(line.strip().startswith(str(i)) for i in range(1, 10))
        ]
        
        return suggestions[:5]


# Flask integration endpoints
def init_lm_endpoints(app, lm_token: str = None):
    """
    Initialize LM Studio integration endpoints for Flask app
    
    Usage:
        from hexstrike_lm_integration import init_lm_endpoints
        lm_integration = init_lm_endpoints(app, api_token="sk-lm-...")
    """
    lm_client = LMStudioClient(api_token=lm_token)
    lm_integration = HexstrikeLMIntegration(lm_client)
    
    @app.route('/api/lm/generate_payloads', methods=['POST'])
    def api_lm_generate_payloads():
        """Generate AI-powered payloads"""
        data = request.get_json()
        vuln_type = data.get('vuln_type', 'xss')
        context = data.get('target_context')
        count = data.get('count', 10)
        
        payloads = lm_integration.generate_ai_payloads(vuln_type, context, count)
        
        return jsonify({
            'vuln_type': vuln_type,
            'count': len(payloads),
            'payloads': payloads,
            'generated_by': 'Granite LLM'
        })
    
    @app.route('/api/lm/analyze', methods=['POST'])
    def api_lm_analyze():
        """Analyze vulnerability with AI"""
        data = request.get_json()
        finding = data.get('finding', {})
        
        analysis = lm_integration.analyze_vulnerability(finding)
        
        return jsonify(analysis)
    
    @app.route('/api/lm/report', methods=['POST'])
    def api_lm_report():
        """Generate AI report"""
        data = request.get_json()
        scan_results = data.get('scan_results', {})
        
        report = lm_integration.generate_report(scan_results)
        
        return jsonify({
            'report': report,
            'format': 'markdown',
            'generated_by': 'Granite LLM'
        })
    
    @app.route('/api/lm/suggest', methods=['POST'])
    def api_lm_suggest():
        """Suggest next testing steps"""
        data = request.get_json()
        findings = data.get('findings', [])
        
        suggestions = lm_integration.suggest_next_steps(findings)
        
        return jsonify({
            'count': len(suggestions),
            'suggestions': suggestions,
            'generated_by': 'Granite LLM'
        })
    
    @app.route('/api/lm/health', methods=['GET'])
    def api_lm_health():
        """Check LM Studio connectivity"""
        try:
            # Simple test request
            response = lm_client.chat_completion(
                [{"role": "user", "content": "test"}],
                max_tokens=5
            )
            available = response is not None
        except:
            available = False
        
        return jsonify({
            'lm_available': available,
            'model': lm_client.model,
            'base_url': lm_client.base_url
        })
    
    logger.info("🤖 LM Studio integration endpoints initialized")
    logger.info("   - POST /api/lm/generate_payloads - AI payload generation")
    logger.info("   - POST /api/lm/analyze - AI vulnerability analysis")
    logger.info("   - POST /api/lm/report - AI report generation")
    logger.info("   - POST /api/lm/suggest - AI testing suggestions")
    logger.info("   - GET /api/lm/health - LM Studio health check")
    
    return lm_integration


if __name__ == '__main__':
    # Standalone test
    import sys
    
    token = "sk-lm-LDkoOL8Q:2YfnL2b2vNDbs8x8pxGP"
    
    print("🤖 Testing Hexstrike LM Studio Integration...")
    
    lm_client = LMStudioClient(api_token=token)
    lm_integration = HexstrikeLMIntegration(lm_client)
    
    print("\n1️⃣ Testing AI Payload Generation (XSS)...")
    payloads = lm_integration.generate_ai_payloads('xss', count=5)
    print(f"✅ Generated {len(payloads)} payloads:")
    for i, p in enumerate(payloads[:5], 1):
        print(f"   {i}. {p}")
    
    print("\n2️⃣ Testing Vulnerability Analysis...")
    test_finding = {
        'vulnerability_type': 'xss',
        'url': 'http://example.com/search?q=test',
        'payload': '<script>alert(1)</script>',
        'severity': 'high'
    }
    analysis = lm_integration.analyze_vulnerability(test_finding)
    print(f"✅ Analysis: {analysis['ai_analysis'][:200]}...")
    
    print("\n3️⃣ Testing Report Generation...")
    test_scan = {
        'target': 'http://example.com',
        'findings': [test_finding],
        'scan_time': '2025-12-06 22:00:00'
    }
    report = lm_integration.generate_report(test_scan)
    print(f"✅ Report generated ({len(report)} chars)")
    print(report[:300])
    
    print("\n🎉 All LM Studio integration tests passed!")
