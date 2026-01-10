#!/usr/bin/env python3
"""
Hexstrike ML Integration Layer

Integrates ML Enhancement with Hexstrike Server.
Provides API endpoints for ML-powered features.

Features:
- False Positive Filtering
- Intelligent Payload Generation
- Adaptive Learning
- ML Statistics

Usage:
    from hexstrike_ml_integration import init_ml_endpoints

    app = Flask(__name__)
    ml_engine = init_ml_endpoints(app)
"""

import logging
import time
from typing import Dict, List, Optional, Any
from flask import Flask, request, jsonify

# Import ML Engine
try:
    from hexstrike.ml import MLEngine
    from hexstrike.ml import FalsePositiveFilter, PayloadGenerator, AdaptiveLearner
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️  Hexstrike ML not available. Install: pip install -r requirements-ml.txt")

logger = logging.getLogger(__name__)


class HexstrikeMLIntegration:
    """
    ML Integration for Hexstrike Server

    Provides ML-powered enhancements to vulnerability scanning.
    """

    def __init__(self, enable_ml: bool = True, config: Optional[Dict] = None):
        """
        Initialize ML Integration

        Args:
            enable_ml: Enable ML features (default: True)
            config: ML configuration dict
        """
        self.enabled = enable_ml and ML_AVAILABLE
        self.config = config or {}

        # Initialize ML Engine if available
        if self.enabled:
            try:
                logger.info("🧠 Initializing Hexstrike ML Engine...")
                self.ml_engine = MLEngine(enable_ml=True, config=self.config)
                logger.info("✅ ML Engine initialized successfully")
            except Exception as e:
                logger.error(f"❌ Failed to initialize ML Engine: {e}")
                self.enabled = False
                self.ml_engine = None
        else:
            self.ml_engine = None

            if not ML_AVAILABLE:
                logger.warning("⚠️  ML dependencies not installed")
                logger.warning("   Install with: pip install -r requirements-ml.txt")

    def filter_false_positives(self, findings: List[Dict]) -> Dict:
        """
        Filter false positives from scan results

        Args:
            findings: List of vulnerability findings

        Returns:
            Dict with verified findings and stats
        """
        if not self.enabled or not self.ml_engine:
            return {
                'verified': findings,
                'false_positives': [],
                'stats': {
                    'total_findings': len(findings),
                    'verified': len(findings),
                    'false_positives': 0,
                    'ml_enabled': False,
                }
            }

        try:
            start_time = time.time()
            result = self.ml_engine.filter_false_positives(findings)
            result['stats']['processing_time'] = time.time() - start_time
            return result
        except Exception as e:
            logger.error(f"❌ ML filtering failed: {e}")
            return {
                'verified': findings,
                'false_positives': [],
                'stats': {
                    'error': str(e),
                    'ml_enabled': False,
                }
            }

    def generate_payloads(self, successful_payloads: Optional[List[str]] = None,
                         vuln_type: str = 'xss', count: int = 50) -> List[str]:
        """
        Generate intelligent payloads using ML

        Args:
            successful_payloads: List of payloads that worked
            vuln_type: Vulnerability type ('xss', 'sqli', 'lfi', 'cmdi')
            count: Number of payloads to generate

        Returns:
            List of generated payloads
        """
        if not self.enabled or not self.ml_engine:
            logger.warning("⚠️  ML disabled, returning empty payload list")
            return []

        try:
            return self.ml_engine.generate_payloads(
                successful_payloads=successful_payloads,
                vuln_type=vuln_type,
                count=count,
                waf_bypass=True
            )
        except Exception as e:
            logger.error(f"❌ ML payload generation failed: {e}")
            return []

    def suggest_payloads(self, target_url: str, vuln_type: Optional[str] = None,
                        limit: int = 50) -> List[str]:
        """
        Suggest payloads for target based on history

        Args:
            target_url: Target URL
            vuln_type: Vulnerability type (optional)
            limit: Max payloads to return

        Returns:
            List of suggested payloads
        """
        if not self.enabled or not self.ml_engine:
            return []

        try:
            return self.ml_engine.suggest_payloads_for_target(
                target_url=target_url,
                vuln_type=vuln_type,
                limit=limit
            )
        except Exception as e:
            logger.error(f"❌ ML payload suggestion failed: {e}")
            return []

    def learn_from_scan(self, scan_result: Dict):
        """
        Learn from scan result for future improvement

        Args:
            scan_result: Scan result with findings
        """
        if not self.enabled or not self.ml_engine:
            return

        try:
            self.ml_engine.learn_from_scan(scan_result)
        except Exception as e:
            logger.error(f"❌ ML learning failed: {e}")

    def get_stats(self) -> Dict:
        """Get ML statistics"""
        if not self.enabled or not self.ml_engine:
            return {
                'ml_enabled': False,
                'ml_available': ML_AVAILABLE,
            }

        try:
            stats = self.ml_engine.get_stats()
            stats['ml_enabled'] = True
            stats['ml_available'] = ML_AVAILABLE
            return stats
        except Exception as e:
            logger.error(f"❌ Failed to get ML stats: {e}")
            return {'error': str(e)}


def init_ml_endpoints(app: Flask, config: Optional[Dict] = None) -> HexstrikeMLIntegration:
    """
    Initialize ML endpoints on Flask app

    Args:
        app: Flask application
        config: ML configuration

    Returns:
        HexstrikeMLIntegration instance
    """
    # Create ML integration
    ml_integration = HexstrikeMLIntegration(enable_ml=True, config=config)

    # ═══════════════════════════════════════════════════════════════════════
    # ML API ENDPOINTS
    # ═══════════════════════════════════════════════════════════════════════

    @app.route("/api/ml/filter", methods=["POST"])
    def ml_filter():
        """
        Filter false positives from findings using ML

        Request JSON:
        {
            "findings": [
                {
                    "baseline_response": {...},
                    "test_response": {...},
                    "payload": "...",
                    "vulnerability_type": "xss"
                }
            ],
            "confidence_threshold": 0.7  // optional
        }

        Response:
        {
            "verified": [...],
            "false_positives": [...],
            "stats": {...}
        }
        """
        try:
            data = request.json
            findings = data.get('findings', [])

            if not findings:
                return jsonify({"error": "No findings provided"}), 400

            # Filter false positives
            result = ml_integration.filter_false_positives(findings)

            logger.info(f"🧠 ML Filter: {len(result['verified'])} verified, "
                       f"{len(result['false_positives'])} FP filtered")

            return jsonify(result)

        except Exception as e:
            logger.error(f"❌ ML filter error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/generate", methods=["POST"])
    def ml_generate():
        """
        Generate intelligent payloads using ML

        Request JSON:
        {
            "successful_payloads": ["<script>alert(1)</script>"],  // optional
            "vuln_type": "xss",  // xss, sqli, lfi, cmdi
            "count": 50,
            "target_url": "http://example.com"  // optional, for suggestions
        }

        Response:
        {
            "payloads": [...],
            "count": 50,
            "vuln_type": "xss",
            "suggestions_included": true
        }
        """
        try:
            data = request.json
            vuln_type = data.get('vuln_type', 'xss')
            count = data.get('count', 50)
            successful = data.get('successful_payloads', [])
            target_url = data.get('target_url')

            payloads = []

            # Generate payloads
            if successful or vuln_type:
                generated = ml_integration.generate_payloads(
                    successful_payloads=successful,
                    vuln_type=vuln_type,
                    count=count
                )
                payloads.extend(generated)

            # Add suggestions if target URL provided
            suggestions_included = False
            if target_url:
                suggestions = ml_integration.suggest_payloads(
                    target_url=target_url,
                    vuln_type=vuln_type,
                    limit=min(20, count // 2)
                )
                payloads.extend(suggestions)
                suggestions_included = len(suggestions) > 0

            # Remove duplicates
            payloads = list(set(payloads))[:count]

            logger.info(f"🧬 ML Generate: {len(payloads)} {vuln_type} payloads "
                       f"(suggestions: {suggestions_included})")

            return jsonify({
                "payloads": payloads,
                "count": len(payloads),
                "vuln_type": vuln_type,
                "suggestions_included": suggestions_included
            })

        except Exception as e:
            logger.error(f"❌ ML generate error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/suggest", methods=["POST"])
    def ml_suggest():
        """
        Suggest payloads for target based on adaptive learning

        Request JSON:
        {
            "target_url": "http://example.com",
            "vuln_type": "xss",  // optional
            "limit": 50
        }

        Response:
        {
            "payloads": [...],
            "count": 10,
            "target_url": "...",
            "fingerprint_found": true
        }
        """
        try:
            data = request.json
            target_url = data.get('target_url')

            if not target_url:
                return jsonify({"error": "target_url required"}), 400

            vuln_type = data.get('vuln_type')
            limit = data.get('limit', 50)

            # Get suggestions
            payloads = ml_integration.suggest_payloads(
                target_url=target_url,
                vuln_type=vuln_type,
                limit=limit
            )

            logger.info(f"💡 ML Suggest: {len(payloads)} payloads for {target_url}")

            return jsonify({
                "payloads": payloads,
                "count": len(payloads),
                "target_url": target_url,
                "fingerprint_found": len(payloads) > 0
            })

        except Exception as e:
            logger.error(f"❌ ML suggest error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/learn", methods=["POST"])
    def ml_learn():
        """
        Record scan results for adaptive learning

        Request JSON:
        {
            "target_url": "http://example.com",
            "findings": [...],
            "total_findings": 10,
            "verified_findings": 8,
            "false_positives": 2,
            "scan_duration": 45.2,
            "tools_used": ["sqlmap", "dalfox"],
            "tech_stack": ["PHP", "MySQL"]  // optional
        }

        Response:
        {
            "success": true,
            "message": "Scan recorded",
            "next_retrain_in": 97
        }
        """
        try:
            scan_result = request.json

            if not scan_result.get('target_url'):
                return jsonify({"error": "target_url required"}), 400

            # Learn from scan
            ml_integration.learn_from_scan(scan_result)

            # Get stats for next retrain info
            stats = ml_integration.get_stats()
            next_retrain = stats.get('adaptive_learning', {}).get('next_retrain_in', 0)

            logger.info(f"📚 ML Learn: Recorded scan of {scan_result['target_url']}")

            return jsonify({
                "success": True,
                "message": "Scan recorded for adaptive learning",
                "next_retrain_in": next_retrain
            })

        except Exception as e:
            logger.error(f"❌ ML learn error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/stats", methods=["GET"])
    def ml_stats():
        """
        Get ML engine statistics

        Response:
        {
            "ml_enabled": true,
            "scans_processed": 10,
            "findings_filtered": 150,
            "false_positives_removed": 28,
            "payloads_generated": 500,
            "models_retrained": 0,
            "adaptive_learning": {...}
        }
        """
        try:
            stats = ml_integration.get_stats()
            return jsonify(stats)

        except Exception as e:
            logger.error(f"❌ ML stats error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/ml/health", methods=["GET"])
    def ml_health():
        """
        Check ML system health

        Response:
        {
            "status": "healthy",
            "ml_available": true,
            "ml_enabled": true,
            "components": {
                "fp_filter": true,
                "payload_generator": true,
                "adaptive_learning": true
            }
        }
        """
        health = {
            "ml_available": ML_AVAILABLE,
            "ml_enabled": ml_integration.enabled,
        }

        if ml_integration.enabled and ml_integration.ml_engine:
            health["status"] = "healthy"
            health["components"] = {
                "fp_filter": ml_integration.ml_engine.fp_filter_enabled,
                "payload_generator": ml_integration.ml_engine.payload_gen_enabled,
                "adaptive_learning": ml_integration.ml_engine.adaptive_learning_enabled,
            }
        else:
            health["status"] = "disabled"
            health["reason"] = "ML not available or disabled"

        return jsonify(health)

    logger.info("✅ ML API endpoints initialized")
    logger.info("   - POST /api/ml/filter - Filter false positives")
    logger.info("   - POST /api/ml/generate - Generate smart payloads")
    logger.info("   - POST /api/ml/suggest - Suggest payloads for target")
    logger.info("   - POST /api/ml/learn - Record scan for learning")
    logger.info("   - GET /api/ml/stats - Get ML statistics")
    logger.info("   - GET /api/ml/health - Check ML health")

    return ml_integration


if __name__ == '__main__':
    # Demo usage
    from flask import Flask

    app = Flask(__name__)
    ml_integration = init_ml_endpoints(app)

    print("\n" + "=" * 70)
    print("  HEXSTRIKE ML INTEGRATION - API ENDPOINTS")
    print("=" * 70)
    print("\nAvailable endpoints:")
    print("  POST /api/ml/filter - Filter false positives")
    print("  POST /api/ml/generate - Generate intelligent payloads")
    print("  POST /api/ml/suggest - Suggest payloads for target")
    print("  POST /api/ml/learn - Record scan for adaptive learning")
    print("  GET /api/ml/stats - Get ML statistics")
    print("  GET /api/ml/health - Check ML system health")
    print("\n" + "=" * 70)

    if ml_integration.enabled:
        print("\n✅ ML Integration: ACTIVE")
        stats = ml_integration.get_stats()
        print(f"   ML Engine initialized: {stats.get('ml_enabled', False)}")
    else:
        print("\n⚠️  ML Integration: DISABLED")
        print("   Install dependencies: pip install -r requirements-ml.txt")
