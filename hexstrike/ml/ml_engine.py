"""
ML Engine - Main orchestrator for all ML features

Combines all ML components into a single unified interface:
- False Positive Filter
- Intelligent Payload Generator
- Adaptive Learning

This is the main entry point for Hexstrike ML enhancement.

Usage:
    from hexstrike.ml import MLEngine

    # Initialize
    ml = MLEngine(enable_ml=True)

    # Filter false positives
    filtered = ml.filter_false_positives(scan_results)

    # Generate new payloads
    payloads = ml.generate_payloads(successful_payloads, vuln_type='xss', count=50)

    # Learn from scan
    ml.learn_from_scan(scan_results)

    # Get statistics
    stats = ml.get_stats()
"""

import os
import time
from typing import List, Dict, Optional, Tuple
from pathlib import Path

try:
    from .fp_filter import FalsePositiveFilter
    from .payload_generator import PayloadGenerator
    from .adaptive_learner import AdaptiveLearner
except ImportError:
    # Fallback for direct execution
    from fp_filter import FalsePositiveFilter
    from payload_generator import PayloadGenerator
    from adaptive_learner import AdaptiveLearner


class MLEngine:
    """
    ML Engine - Unified interface for all ML features

    Orchestrates:
    - False Positive Filter (reduce FP from 20% to 5-7%)
    - Payload Generator (generate 50+ WAF bypass variants)
    - Adaptive Learning (learn from every scan)
    """

    def __init__(self, enable_ml: bool = True, config: Optional[Dict] = None):
        """
        Initialize ML Engine

        Args:
            enable_ml: Whether to enable ML features (default: True)
            config: Configuration dict (optional)
                - fp_filter_enabled: bool (default: True)
                - payload_gen_enabled: bool (default: True)
                - adaptive_learning_enabled: bool (default: True)
                - fp_confidence_threshold: float (default: 0.7)
                - auto_retrain: bool (default: True)
                - retrain_interval: int (default: 100 scans)
        """
        self.enabled = enable_ml
        self.config = config or {}

        # Default configuration
        self.fp_filter_enabled = self.config.get('fp_filter_enabled', True)
        self.payload_gen_enabled = self.config.get('payload_gen_enabled', True)
        self.adaptive_learning_enabled = self.config.get('adaptive_learning_enabled', True)

        self.fp_confidence_threshold = self.config.get('fp_confidence_threshold', 0.7)
        self.auto_retrain = self.config.get('auto_retrain', True)
        self.retrain_interval = self.config.get('retrain_interval', 100)

        # Initialize components
        self.fp_filter = None
        self.payload_generator = None
        self.adaptive_learner = None

        if self.enabled:
            self._initialize_components()

        # Statistics
        self.stats = {
            'scans_processed': 0,
            'findings_filtered': 0,
            'false_positives_removed': 0,
            'payloads_generated': 0,
            'models_retrained': 0,
        }

    def _initialize_components(self):
        """Initialize ML components"""
        print("🧠 Initializing Hexstrike ML Engine...")

        # 1. False Positive Filter
        if self.fp_filter_enabled:
            try:
                self.fp_filter = FalsePositiveFilter()
                # Try to load pre-trained model
                try:
                    self.fp_filter.load_model()
                    print("   ✅ False Positive Filter loaded")
                except FileNotFoundError:
                    print("   ⚠️  No pre-trained FP filter found (will use default behavior)")
            except Exception as e:
                print(f"   ⚠️  Failed to initialize FP Filter: {e}")
                self.fp_filter_enabled = False

        # 2. Payload Generator
        if self.payload_gen_enabled:
            try:
                self.payload_generator = PayloadGenerator()
                # Try to load saved payloads
                payload_path = os.path.join(
                    os.path.expanduser('~'),
                    '.hexstrike',
                    'successful_payloads.json'
                )
                if os.path.exists(payload_path):
                    self.payload_generator.load_payloads(payload_path)
                print("   ✅ Payload Generator initialized")
            except Exception as e:
                print(f"   ⚠️  Failed to initialize Payload Generator: {e}")
                self.payload_gen_enabled = False

        # 3. Adaptive Learning
        if self.adaptive_learning_enabled:
            try:
                self.adaptive_learner = AdaptiveLearner()
                self.adaptive_learner.retrain_interval = self.retrain_interval
                print("   ✅ Adaptive Learning initialized")
            except Exception as e:
                print(f"   ⚠️  Failed to initialize Adaptive Learning: {e}")
                self.adaptive_learning_enabled = False

        print("✅ ML Engine ready!\n")

    def filter_false_positives(self, findings: List[Dict],
                               confidence_threshold: Optional[float] = None) -> Dict:
        """
        Filter false positives from vulnerability findings

        Args:
            findings: List of vulnerability findings
            confidence_threshold: Minimum confidence (default: from config)

        Returns:
            Dict with:
                - verified: List of true positives
                - false_positives: List of filtered FPs
                - stats: Statistics
        """
        if not self.enabled or not self.fp_filter_enabled or not self.fp_filter:
            # ML disabled, return all findings as verified
            return {
                'verified': findings,
                'false_positives': [],
                'stats': {
                    'total_findings': len(findings),
                    'verified': len(findings),
                    'false_positives': 0,
                    'fp_rate': 0.0,
                    'ml_enabled': False,
                }
            }

        threshold = confidence_threshold or self.fp_confidence_threshold

        print(f"🧠 ML: Filtering {len(findings)} findings...")
        start_time = time.time()

        try:
            result = self.fp_filter.filter_findings(findings, threshold)

            elapsed = time.time() - start_time
            fp_count = len(result['false_positives'])

            print(f"   ✅ Filtered {fp_count} false positives ({elapsed:.2f}s)")
            print(f"   ✅ Verified {len(result['verified'])} real vulnerabilities")

            # Update stats
            self.stats['findings_filtered'] += len(findings)
            self.stats['false_positives_removed'] += fp_count

            return result

        except Exception as e:
            print(f"   ⚠️  FP filtering failed: {e}")
            # Fallback: return all findings
            return {
                'verified': findings,
                'false_positives': [],
                'stats': {
                    'total_findings': len(findings),
                    'verified': len(findings),
                    'false_positives': 0,
                    'error': str(e),
                }
            }

    def generate_payloads(self, successful_payloads: Optional[List[str]] = None,
                         vuln_type: str = 'xss', count: int = 50,
                         waf_bypass: bool = True) -> List[str]:
        """
        Generate new payloads using ML

        Args:
            successful_payloads: List of payloads that worked (optional)
            vuln_type: Vulnerability type ('xss', 'sqli', 'lfi', 'cmdi')
            count: Number of payloads to generate
            waf_bypass: Include WAF bypass mutations (default: True)

        Returns:
            List of generated payloads
        """
        if not self.enabled or not self.payload_gen_enabled or not self.payload_generator:
            print("⚠️  Payload generation disabled")
            return []

        print(f"🧬 ML: Generating {count} {vuln_type} payloads...")
        start_time = time.time()

        try:
            # Train on successful payloads if provided
            if successful_payloads:
                self.payload_generator.train(successful_payloads, vuln_type)

            # Generate payloads
            payloads = self.payload_generator.generate(
                count=count,
                vuln_type=vuln_type,
                include_mutations=waf_bypass
            )

            elapsed = time.time() - start_time
            print(f"   ✅ Generated {len(payloads)} payloads ({elapsed:.2f}s)")

            # Update stats
            self.stats['payloads_generated'] += len(payloads)

            return payloads

        except Exception as e:
            print(f"   ⚠️  Payload generation failed: {e}")
            return []

    def suggest_payloads_for_target(self, target_url: str, vuln_type: Optional[str] = None,
                                    limit: int = 50) -> List[str]:
        """
        Suggest payloads for a target based on historical success

        Uses adaptive learning to suggest payloads that worked on similar targets.

        Args:
            target_url: Target URL
            vuln_type: Vulnerability type (optional, None = all)
            limit: Maximum payloads to return

        Returns:
            List of suggested payloads
        """
        if not self.enabled or not self.adaptive_learning_enabled or not self.adaptive_learner:
            print("⚠️  Adaptive learning disabled")
            return []

        print(f"💡 ML: Suggesting payloads for {target_url}...")

        try:
            payloads = self.adaptive_learner.suggest_payloads(
                target_url=target_url,
                vuln_type=vuln_type,
                limit=limit
            )

            return payloads

        except Exception as e:
            print(f"   ⚠️  Payload suggestion failed: {e}")
            return []

    def learn_from_scan(self, scan_result: Dict):
        """
        Learn from a scan result

        Records the scan in adaptive learning database and checks if models
        should be retrained.

        Args:
            scan_result: Scan result dict with:
                - target_url: str
                - findings: List[Dict]
                - total_findings: int
                - verified_findings: int
                - false_positives: int
                - scan_duration: float
                - tools_used: List[str]
                - tech_stack: List[str] (optional)
        """
        if not self.enabled or not self.adaptive_learning_enabled or not self.adaptive_learner:
            return

        print(f"📚 ML: Learning from scan...")

        try:
            # Record scan
            self.adaptive_learner.record_scan(scan_result)

            # Update stats
            self.stats['scans_processed'] += 1

            # Check if we should retrain models
            if self.auto_retrain:
                retrained = self.adaptive_learner.check_and_retrain(
                    fp_filter=self.fp_filter if self.fp_filter_enabled else None,
                    payload_generator=self.payload_generator if self.payload_gen_enabled else None
                )

                if retrained:
                    self.stats['models_retrained'] += 1

        except Exception as e:
            print(f"   ⚠️  Learning failed: {e}")

    def get_stats(self) -> Dict:
        """
        Get ML Engine statistics

        Returns:
            Dict with statistics including:
                - ML engine stats (scans processed, findings filtered, etc.)
                - Adaptive learning stats (if enabled)
        """
        stats = self.stats.copy()

        # Add adaptive learning stats
        if self.adaptive_learning_enabled and self.adaptive_learner:
            try:
                al_stats = self.adaptive_learner.get_statistics()
                stats['adaptive_learning'] = al_stats
            except Exception as e:
                stats['adaptive_learning_error'] = str(e)

        return stats

    def print_stats(self):
        """Print ML Engine statistics"""
        print("\n📊 ML Engine Statistics")
        print("=" * 60)

        stats = self.get_stats()

        print(f"Scans processed: {stats['scans_processed']}")
        print(f"Findings filtered: {stats['findings_filtered']}")
        print(f"False positives removed: {stats['false_positives_removed']}")
        print(f"Payloads generated: {stats['payloads_generated']}")
        print(f"Models retrained: {stats['models_retrained']}")

        if 'adaptive_learning' in stats:
            print("\nAdaptive Learning:")
            al = stats['adaptive_learning']
            print(f"  Total scans: {al.get('total_scans', 0)}")
            print(f"  Total findings: {al.get('total_findings', 0)}")
            print(f"  Verified findings: {al.get('verified_findings', 0)}")
            print(f"  False positives: {al.get('false_positives', 0)}")

            if al.get('successful_payloads'):
                print(f"  Successful payloads:")
                for vuln_type, count in al['successful_payloads'].items():
                    print(f"    - {vuln_type}: {count}")

            print(f"  Next retrain in: {al.get('next_retrain_in', 0)} scans")

        print("=" * 60)

    def close(self):
        """Clean up resources"""
        if self.adaptive_learner:
            self.adaptive_learner.close()


# Convenience function
def create_ml_engine(enable_ml: bool = True, config: Optional[Dict] = None) -> MLEngine:
    """
    Create and return an ML Engine instance

    Args:
        enable_ml: Whether to enable ML features
        config: Configuration dict

    Returns:
        MLEngine instance
    """
    return MLEngine(enable_ml=enable_ml, config=config)


if __name__ == '__main__':
    # Demo usage
    print("ML Engine - Demo")
    print("=" * 60)

    # Create ML engine
    ml = create_ml_engine(enable_ml=True)

    # Example: Filter false positives
    print("\n1. FALSE POSITIVE FILTERING")
    print("-" * 60)

    findings = [
        {
            'baseline_response': {'text': 'Normal response', 'status_code': 200, 'elapsed': 0.5},
            'test_response': {'text': 'Response with <script>alert(1)</script>', 'status_code': 200, 'elapsed': 0.52},
            'payload': '<script>alert(1)</script>',
            'vulnerability_type': 'xss',
        }
    ]

    # This would fail without a trained model, but demonstrates the API
    # result = ml.filter_false_positives(findings)

    # Example: Generate payloads
    print("\n2. PAYLOAD GENERATION")
    print("-" * 60)

    payloads = ml.generate_payloads(
        successful_payloads=['<script>alert(1)</script>'],
        vuln_type='xss',
        count=10
    )

    print(f"Generated {len(payloads)} payloads:")
    for i, p in enumerate(payloads[:5], 1):
        print(f"  {i}. {p}")

    # Example: Learn from scan
    print("\n3. ADAPTIVE LEARNING")
    print("-" * 60)

    scan_result = {
        'target_url': 'http://example.com',
        'total_findings': 5,
        'verified_findings': 4,
        'false_positives': 1,
        'scan_duration': 30.5,
        'tools_used': ['dalfox', 'sqlmap'],
        'tech_stack': ['PHP', 'MySQL'],
        'findings': [
            {
                'vulnerability_type': 'xss',
                'payload': '<script>alert(1)</script>',
                'success': True,
                'verified': True,
                'confidence': 0.95,
            }
        ]
    }

    ml.learn_from_scan(scan_result)

    # Print statistics
    ml.print_stats()

    # Cleanup
    ml.close()
