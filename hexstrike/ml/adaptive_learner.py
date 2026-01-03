"""
Adaptive Learning System - Learn from every scan

Continuously improves ML models by learning from user's scans.
Stores successful payloads, verified vulnerabilities, and false positives
in SQLite database for automatic retraining.

Features:
- SQLite database for scan history
- Automatic model retraining (every 100 scans)
- Target fingerprinting (tech stack detection)
- Payload effectiveness tracking
- User feedback integration

Usage:
    learner = AdaptiveLearner()

    # After each scan
    learner.record_scan(scan_results)

    # Automatic retraining every 100 scans
    learner.check_and_retrain()

    # Get suggested payloads for similar targets
    payloads = learner.suggest_payloads(target_url)
"""

import sqlite3
import json
import time
import os
from pathlib import Path
from typing import List, Dict, Optional, Set
from collections import Counter


class AdaptiveLearner:
    """
    Adaptive Learning System

    Learns from every scan to continuously improve detection accuracy.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize Adaptive Learner

        Args:
            db_path: Path to SQLite database (default: ~/.hexstrike/learning.db)
        """
        if db_path is None:
            # Default path: ~/.hexstrike/learning.db
            hexstrike_dir = os.path.join(os.path.expanduser('~'), '.hexstrike')
            os.makedirs(hexstrike_dir, exist_ok=True)
            db_path = os.path.join(hexstrike_dir, 'learning.db')

        self.db_path = db_path
        self.conn = None

        # Initialize database
        self._init_database()

        # Retrain interval (every N scans)
        self.retrain_interval = 100

    def _init_database(self):
        """Initialize SQLite database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Return rows as dicts

        cursor = self.conn.cursor()

        # Table 1: Scan Results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_findings INTEGER DEFAULT 0,
                verified_findings INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                scan_duration_seconds REAL,
                tools_used TEXT,
                tech_stack TEXT
            )
        ''')

        # Table 2: Vulnerability Findings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target_url TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                success BOOLEAN DEFAULT 0,
                verified BOOLEAN DEFAULT NULL,
                confidence REAL,
                response_snippet TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')

        # Table 3: Successful Payloads (for quick lookup)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS successful_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_type TEXT NOT NULL,
                payload TEXT NOT NULL UNIQUE,
                success_count INTEGER DEFAULT 1,
                target_tech_stack TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 4: Target Fingerprints
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL UNIQUE,
                tech_stack TEXT,
                server TEXT,
                frameworks TEXT,
                vulnerabilities_found TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 5: Model Training History
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                training_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                samples_used INTEGER,
                accuracy REAL,
                notes TEXT
            )
        ''')

        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vulnerability_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_success ON findings(success)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_payloads_vuln_type ON successful_payloads(vulnerability_type)')

        self.conn.commit()

        print(f"✅ Adaptive Learning database initialized: {self.db_path}")

    def record_scan(self, scan_result: Dict):
        """
        Record a scan result in the database

        Args:
            scan_result: Dict with scan results:
                - target_url: str
                - findings: List[Dict] (vulnerability findings)
                - total_findings: int
                - verified_findings: int
                - false_positives: int
                - scan_duration: float (seconds)
                - tools_used: List[str]
                - tech_stack: List[str] (optional)
        """
        cursor = self.conn.cursor()

        # Extract data
        target_url = scan_result.get('target_url', 'unknown')
        total_findings = scan_result.get('total_findings', 0)
        verified_findings = scan_result.get('verified_findings', 0)
        false_positives = scan_result.get('false_positives', 0)
        scan_duration = scan_result.get('scan_duration', 0.0)
        tools_used = json.dumps(scan_result.get('tools_used', []))
        tech_stack = json.dumps(scan_result.get('tech_stack', []))

        # Insert scan record
        cursor.execute('''
            INSERT INTO scans (
                target_url, total_findings, verified_findings, false_positives,
                scan_duration_seconds, tools_used, tech_stack
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target_url, total_findings, verified_findings, false_positives,
              scan_duration, tools_used, tech_stack))

        scan_id = cursor.lastrowid

        # Insert findings
        findings = scan_result.get('findings', [])
        for finding in findings:
            vuln_type = finding.get('vulnerability_type', 'unknown')
            payload = finding.get('payload', '')
            success = finding.get('success', False)
            verified = finding.get('verified', None)
            confidence = finding.get('confidence', 0.0)
            response_snippet = finding.get('response', '')[:500]  # First 500 chars

            cursor.execute('''
                INSERT INTO findings (
                    scan_id, target_url, vulnerability_type, payload,
                    success, verified, confidence, response_snippet
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, target_url, vuln_type, payload, success, verified,
                  confidence, response_snippet))

            # If successful, add to successful_payloads table
            if success and verified != False:  # True or None (not explicitly marked as FP)
                self._record_successful_payload(
                    vuln_type,
                    payload,
                    tech_stack
                )

        # Update target fingerprint
        if 'tech_stack' in scan_result or 'server' in scan_result:
            self._update_target_fingerprint(scan_result)

        self.conn.commit()

        print(f"✅ Recorded scan of {target_url}: {total_findings} findings ({verified_findings} verified)")

        return scan_id

    def _record_successful_payload(self, vuln_type: str, payload: str, tech_stack: str):
        """Record a successful payload"""
        cursor = self.conn.cursor()

        # Check if payload already exists
        cursor.execute(
            'SELECT id, success_count FROM successful_payloads WHERE payload = ?',
            (payload,)
        )
        existing = cursor.fetchone()

        if existing:
            # Update success count and last_used
            cursor.execute('''
                UPDATE successful_payloads
                SET success_count = success_count + 1,
                    last_used = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (existing['id'],))
        else:
            # Insert new successful payload
            cursor.execute('''
                INSERT INTO successful_payloads (
                    vulnerability_type, payload, target_tech_stack
                ) VALUES (?, ?, ?)
            ''', (vuln_type, payload, tech_stack))

    def _update_target_fingerprint(self, scan_result: Dict):
        """Update or create target fingerprint"""
        cursor = self.conn.cursor()

        target_url = scan_result.get('target_url', 'unknown')
        tech_stack = json.dumps(scan_result.get('tech_stack', []))
        server = scan_result.get('server', '')
        frameworks = json.dumps(scan_result.get('frameworks', []))

        # Get vulnerabilities found
        vulns_found = [f.get('vulnerability_type') for f in scan_result.get('findings', [])
                       if f.get('success', False)]
        vulnerabilities = json.dumps(list(set(vulns_found)))

        # Upsert fingerprint
        cursor.execute('''
            INSERT INTO target_fingerprints (
                target_url, tech_stack, server, frameworks, vulnerabilities_found
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_url) DO UPDATE SET
                tech_stack = excluded.tech_stack,
                server = excluded.server,
                frameworks = excluded.frameworks,
                vulnerabilities_found = excluded.vulnerabilities_found,
                last_scanned = CURRENT_TIMESTAMP
        ''', (target_url, tech_stack, server, frameworks, vulnerabilities))

    def suggest_payloads(self, target_url: str, vuln_type: Optional[str] = None,
                        limit: int = 50) -> List[str]:
        """
        Suggest payloads for a target based on historical success

        Args:
            target_url: Target URL
            vuln_type: Vulnerability type (optional, None = all types)
            limit: Maximum payloads to return

        Returns:
            List of suggested payloads (sorted by success rate)
        """
        cursor = self.conn.cursor()

        # Detect target tech stack (if we've seen it before)
        cursor.execute(
            'SELECT tech_stack FROM target_fingerprints WHERE target_url = ?',
            (target_url,)
        )
        fingerprint = cursor.fetchone()

        if fingerprint:
            tech_stack = fingerprint['tech_stack']
            print(f"🔍 Found fingerprint for {target_url}: {tech_stack}")

            # Get payloads that worked on similar tech stack
            query = '''
                SELECT payload, vulnerability_type, success_count
                FROM successful_payloads
                WHERE target_tech_stack LIKE ?
            '''
            params = [f'%{tech_stack}%']
        else:
            # No fingerprint, just get most successful payloads
            print(f"🔍 No fingerprint for {target_url}, using global successful payloads")
            query = '''
                SELECT payload, vulnerability_type, success_count
                FROM successful_payloads
            '''
            params = []

        # Filter by vuln type if specified
        if vuln_type:
            query += ' AND vulnerability_type = ?'
            params.append(vuln_type)

        # Order by success count
        query += ' ORDER BY success_count DESC, last_used DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)
        results = cursor.fetchall()

        payloads = [row['payload'] for row in results]

        print(f"💡 Suggested {len(payloads)} payloads for {target_url}")

        return payloads

    def get_scan_count(self) -> int:
        """Get total number of scans recorded"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM scans')
        return cursor.fetchone()['count']

    def get_successful_payload_count(self, vuln_type: Optional[str] = None) -> int:
        """Get count of successful payloads"""
        cursor = self.conn.cursor()

        if vuln_type:
            cursor.execute(
                'SELECT COUNT(*) as count FROM successful_payloads WHERE vulnerability_type = ?',
                (vuln_type,)
            )
        else:
            cursor.execute('SELECT COUNT(*) as count FROM successful_payloads')

        return cursor.fetchone()['count']

    def check_and_retrain(self, fp_filter=None, payload_generator=None) -> bool:
        """
        Check if models should be retrained and retrain if needed

        Retrains every `retrain_interval` scans (default: 100)

        Args:
            fp_filter: FalsePositiveFilter instance (optional)
            payload_generator: PayloadGenerator instance (optional)

        Returns:
            bool: True if retrained, False otherwise
        """
        scan_count = self.get_scan_count()

        # Check if we should retrain
        if scan_count % self.retrain_interval != 0 or scan_count == 0:
            return False

        print(f"\n🔄 Retraining models (scan count: {scan_count})...")

        retrained = False

        # Retrain False Positive Filter
        if fp_filter:
            training_data = self._get_fp_training_data()
            if len(training_data) >= 10:
                print(f"   Retraining FP Filter with {len(training_data)} examples...")
                fp_filter.train(training_data)
                fp_filter.save_model()

                # Record training
                self._record_training('fp_filter', len(training_data))
                retrained = True

        # Retrain Payload Generator
        if payload_generator:
            for vuln_type in ['xss', 'sqli', 'lfi', 'cmdi']:
                payloads = self._get_successful_payloads(vuln_type)
                if payloads:
                    print(f"   Retraining Payload Generator ({vuln_type}) with {len(payloads)} payloads...")
                    payload_generator.train(payloads, vuln_type)
                    retrained = True

            # Save payloads
            if hasattr(payload_generator, 'save_payloads'):
                payload_path = os.path.join(os.path.dirname(self.db_path), 'successful_payloads.json')
                payload_generator.save_payloads(payload_path)

            # Record training
            total_payloads = sum(
                self.get_successful_payload_count(vt)
                for vt in ['xss', 'sqli', 'lfi', 'cmdi']
            )
            self._record_training('payload_generator', total_payloads)

        if retrained:
            print(f"✅ Models retrained successfully!")
        else:
            print(f"⚠️  Not enough data for retraining yet")

        return retrained

    def _get_fp_training_data(self) -> List:
        """Get training data for False Positive Filter"""
        cursor = self.conn.cursor()

        # Get verified findings (both true positives and false positives)
        cursor.execute('''
            SELECT * FROM findings
            WHERE verified IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 1000
        ''')

        findings = cursor.fetchall()

        # Convert to training format
        # TODO: This would need actual response data
        # For now, return empty list (would need to store full responses)
        # This is a placeholder for future enhancement

        return []

    def _get_successful_payloads(self, vuln_type: str) -> List[str]:
        """Get successful payloads for a vulnerability type"""
        cursor = self.conn.cursor()

        cursor.execute('''
            SELECT DISTINCT payload
            FROM successful_payloads
            WHERE vulnerability_type = ?
            ORDER BY success_count DESC
            LIMIT 100
        ''', (vuln_type,))

        return [row['payload'] for row in cursor.fetchall()]

    def _record_training(self, model_name: str, samples_used: int, accuracy: float = None):
        """Record model training in history"""
        cursor = self.conn.cursor()

        cursor.execute('''
            INSERT INTO training_history (model_name, samples_used, accuracy)
            VALUES (?, ?, ?)
        ''', (model_name, samples_used, accuracy))

        self.conn.commit()

    def get_statistics(self) -> Dict:
        """Get learning statistics"""
        cursor = self.conn.cursor()

        stats = {}

        # Total scans
        stats['total_scans'] = self.get_scan_count()

        # Total findings
        cursor.execute('SELECT COUNT(*) as count FROM findings')
        stats['total_findings'] = cursor.fetchone()['count']

        # Verified findings
        cursor.execute('SELECT COUNT(*) as count FROM findings WHERE verified = 1')
        stats['verified_findings'] = cursor.fetchone()['count']

        # False positives
        cursor.execute('SELECT COUNT(*) as count FROM findings WHERE verified = 0')
        stats['false_positives'] = cursor.fetchone()['count']

        # Successful payloads by type
        stats['successful_payloads'] = {}
        for vuln_type in ['xss', 'sqli', 'lfi', 'cmdi', 'other']:
            count = self.get_successful_payload_count(vuln_type)
            if count > 0:
                stats['successful_payloads'][vuln_type] = count

        # Target fingerprints
        cursor.execute('SELECT COUNT(*) as count FROM target_fingerprints')
        stats['target_fingerprints'] = cursor.fetchone()['count']

        # Training history
        cursor.execute('SELECT COUNT(*) as count FROM training_history')
        stats['training_count'] = cursor.fetchone()['count']

        # Next retrain
        next_retrain = self.retrain_interval - (stats['total_scans'] % self.retrain_interval)
        stats['next_retrain_in'] = next_retrain

        return stats

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


if __name__ == '__main__':
    # Demo usage
    print("Adaptive Learning System - Demo")
    print("=" * 60)

    # Create learner
    learner = AdaptiveLearner()

    # Example scan result
    scan_result = {
        'target_url': 'http://example.com',
        'total_findings': 10,
        'verified_findings': 8,
        'false_positives': 2,
        'scan_duration': 45.2,
        'tools_used': ['sqlmap', 'dalfox', 'nuclei'],
        'tech_stack': ['PHP', 'MySQL', 'Apache'],
        'findings': [
            {
                'vulnerability_type': 'xss',
                'payload': '<script>alert(1)</script>',
                'success': True,
                'verified': True,
                'confidence': 0.95,
                'response': '<html>Search: <script>alert(1)</script></html>'
            },
            {
                'vulnerability_type': 'sqli',
                'payload': "' OR '1'='1",
                'success': True,
                'verified': True,
                'confidence': 0.88,
                'response': 'SQL error: syntax error near...'
            },
        ]
    }

    # Record scan
    scan_id = learner.record_scan(scan_result)
    print(f"Scan ID: {scan_id}")

    # Get statistics
    print("\n📊 Learning Statistics:")
    stats = learner.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Suggest payloads
    print("\n💡 Suggested payloads for http://example.com:")
    payloads = learner.suggest_payloads('http://example.com', vuln_type='xss', limit=5)
    for i, payload in enumerate(payloads, 1):
        print(f"  {i}. {payload}")

    # Close
    learner.close()
