#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════╗
║     Hash Collision & Length Extension Attack Scanner        ║
║              Part of AlBaTTaR BUGS Framework                 ║
╚══════════════════════════════════════════════════════════════╝

Description: Advanced scanner for detecting hash collision vulnerabilities
             and length extension attacks in cryptographic implementations

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

import hashlib
import hmac
import struct
import binascii
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
import requests
import time
import re

class HashCollisionScanner:
    """
    Scanner for detecting hash collision and length extension vulnerabilities
    """
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize the Hash Collision Scanner
        
        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Scanner configuration
        self.timeout = self.config.get('timeout', 15)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_retries = self.config.get('max_retries', 3)
        
        # Test payloads and patterns
        self.hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        self.vulnerable_patterns = [
            r'signature[_\-]?mismatch',
            r'invalid[_\-]?signature',
            r'hash[_\-]?verification[_\-]?failed',
            r'authentication[_\-]?failed'
        ]
        
    def scan(self) -> List[Dict]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        print(f"[*] Starting Hash Collision scan on: {self.target}")
        
        # Test different attack vectors
        self._test_hash_length_extension()
        self._test_collision_attacks()
        self._test_weak_hash_algorithms()
        self._test_signature_bypass()
        self._test_timing_attacks()
        self._test_hmac_vulnerabilities()
        
        print(f"[+] Scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _test_hash_length_extension(self):
        """Test for hash length extension vulnerabilities"""
        print("[*] Testing for hash length extension attacks...")
        
        # Algorithms vulnerable to length extension
        vulnerable_algos = ['md5', 'sha1', 'sha256']
        
        for algo in vulnerable_algos:
            # Test common parameter names
            test_params = [
                'signature', 'sig', 'hash', 'token',
                'auth', 'key', 'mac', 'hmac'
            ]
            
            for param in test_params:
                if self._test_length_extension_param(param, algo):
                    self.vulnerabilities.append({
                        'type': 'Hash Length Extension',
                        'severity': 'high',
                        'url': self.target,
                        'parameter': param,
                        'algorithm': algo,
                        'description': f'Hash length extension attack possible on {param} using {algo}',
                        'impact': 'Attacker can forge valid signatures without knowing the secret key',
                        'remediation': 'Use HMAC instead of hash(secret + message) construction',
                        'cwe': 'CWE-327',
                        'confidence': 85
                    })
    
    def _test_length_extension_param(self, param: str, algo: str) -> bool:
        """
        Test specific parameter for length extension vulnerability
        
        Args:
            param: Parameter name to test
            algo: Hash algorithm to test
            
        Returns:
            True if vulnerable, False otherwise
        """
        try:
            # Parse URL and extract parameters
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            
            # Check if parameter exists
            if param not in params:
                # Try adding the parameter
                test_url = f"{self.target}{'&' if '?' in self.target else '?'}{param}=test"
                response1 = self._make_request(test_url)
                if not response1:
                    return False
                
                # Generate length extension attack payload
                original_data = b"test"
                secret_length = 16  # Assume common secret length
                additional_data = b"&admin=true"
                
                # Craft extended hash
                extended_hash = self._craft_length_extension(
                    original_data, additional_data, secret_length, algo
                )
                
                # Test with extended payload
                test_url2 = test_url + urlencode({'extension': additional_data.decode()})
                test_url2 += f"&{param}={extended_hash}"
                
                response2 = self._make_request(test_url2)
                
                if response2 and response2.status_code == 200:
                    # Check for success indicators
                    if self._check_authentication_success(response2):
                        return True
            
            return False
            
        except Exception as e:
            print(f"[!] Error testing length extension on {param}: {str(e)}")
            return False
    
    def _craft_length_extension(self, original: bytes, additional: bytes, 
                                secret_len: int, algo: str) -> str:
        """
        Craft a length extension attack payload
        
        Args:
            original: Original data
            additional: Data to append
            secret_len: Length of secret key
            algo: Hash algorithm
            
        Returns:
            Forged hash value
        """
        # Get hash function
        hash_func = getattr(hashlib, algo)
        block_size = 64 if algo in ['md5', 'sha1', 'sha256'] else 128
        
        # Calculate padding for original message
        original_len = secret_len + len(original)
        padding = self._calculate_padding(original_len, block_size)
        
        # Create extended message
        extended = original + padding + additional
        
        # Simulate hash with extended data
        # Note: This is a simplified version
        h = hash_func()
        h.update(extended)
        
        return h.hexdigest()
    
    def _calculate_padding(self, message_len: int, block_size: int) -> bytes:
        """Calculate MD padding for hash length extension"""
        # MD padding: 1 bit followed by zeros, then length in bits
        padding_len = (block_size - (message_len + 9) % block_size) % block_size
        padding = b'\x80' + (b'\x00' * padding_len)
        padding += struct.pack('>Q', message_len * 8)
        return padding
    
    def _test_collision_attacks(self):
        """Test for hash collision vulnerabilities"""
        print("[*] Testing for hash collision attacks...")
        
        # Test MD5 collisions (using known collision pairs)
        md5_collisions = [
            # FastColl collision pair
            (
                bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89'
                            '55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b'
                            'd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0'
                            'e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'),
                bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89'
                            '55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b'
                            'd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0'
                            'e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
            )
        ]
        
        for collision1, collision2 in md5_collisions:
            # Verify these actually collide
            hash1 = hashlib.md5(collision1).hexdigest()
            hash2 = hashlib.md5(collision2).hexdigest()
            
            if hash1 == hash2:
                # Test if application accepts both
                if self._test_collision_pair(collision1, collision2):
                    self.vulnerabilities.append({
                        'type': 'MD5 Hash Collision',
                        'severity': 'high',
                        'url': self.target,
                        'description': 'Application accepts MD5 collision pairs',
                        'impact': 'Attacker can create different inputs with same hash',
                        'remediation': 'Use collision-resistant hash functions (SHA-256+)',
                        'cwe': 'CWE-328',
                        'confidence': 95
                    })
    
    def _test_collision_pair(self, data1: bytes, data2: bytes) -> bool:
        """Test if application accepts collision pair"""
        try:
            # Test with file upload if available
            files1 = {'file': ('test1.bin', data1, 'application/octet-stream')}
            files2 = {'file': ('test2.bin', data2, 'application/octet-stream')}
            
            response1 = self.session.post(self.target, files=files1, 
                                         timeout=self.timeout, verify=self.verify_ssl)
            response2 = self.session.post(self.target, files=files2,
                                         timeout=self.timeout, verify=self.verify_ssl)
            
            # Check if both files are accepted with same hash
            if response1.status_code == 200 and response2.status_code == 200:
                # Look for hash in response
                hash_pattern = r'[a-f0-9]{32}'  # MD5 hash pattern
                hash1_found = re.search(hash_pattern, response1.text)
                hash2_found = re.search(hash_pattern, response2.text)
                
                if hash1_found and hash2_found:
                    return hash1_found.group() == hash2_found.group()
            
            return False
            
        except Exception as e:
            print(f"[!] Error testing collision pair: {str(e)}")
            return False
    
    def _test_weak_hash_algorithms(self):
        """Test for usage of weak hash algorithms"""
        print("[*] Testing for weak hash algorithm usage...")
        
        weak_algorithms = {
            'md5': {'severity': 'high', 'reason': 'Cryptographically broken'},
            'sha1': {'severity': 'medium', 'reason': 'Collision attacks exist'},
            'md4': {'severity': 'critical', 'reason': 'Severely broken'}
        }
        
        try:
            response = self._make_request(self.target)
            if not response:
                return
            
            # Check headers and response for hash algorithm indicators
            combined_text = str(response.headers) + response.text
            
            for algo, info in weak_algorithms.items():
                patterns = [
                    rf'\b{algo}\b',
                    rf'algorithm["\']?\s*[:=]\s*["\']?{algo}',
                    rf'{algo}[_\-]hash',
                    rf'hash[_\-]algorithm.*{algo}'
                ]
                
                for pattern in patterns:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'Weak Hash Algorithm',
                            'severity': info['severity'],
                            'url': self.target,
                            'algorithm': algo.upper(),
                            'description': f'Application uses weak hash algorithm: {algo.upper()}',
                            'impact': info['reason'],
                            'remediation': 'Use SHA-256 or stronger hash functions',
                            'cwe': 'CWE-327',
                            'confidence': 75
                        })
                        break
                        
        except Exception as e:
            print(f"[!] Error testing weak algorithms: {str(e)}")
    
    def _test_signature_bypass(self):
        """Test for signature bypass vulnerabilities"""
        print("[*] Testing for signature bypass...")
        
        test_cases = [
            # Missing signature
            {'remove_sig': True},
            # Empty signature
            {'sig': ''},
            # Null byte injection
            {'sig': 'valid_sig\x00malicious'},
            # Array manipulation
            {'sig': ['valid_sig', 'malicious']},
            # Type confusion
            {'sig': 0},
            {'sig': False},
            {'sig': None}
        ]
        
        for test_case in test_cases:
            if self._test_signature_manipulation(test_case):
                self.vulnerabilities.append({
                    'type': 'Signature Bypass',
                    'severity': 'critical',
                    'url': self.target,
                    'test_case': str(test_case),
                    'description': 'Signature verification can be bypassed',
                    'impact': 'Complete authentication bypass possible',
                    'remediation': 'Implement proper signature verification',
                    'cwe': 'CWE-347',
                    'confidence': 90
                })
    
    def _test_signature_manipulation(self, test_case: Dict) -> bool:
        """Test signature manipulation"""
        try:
            # Build test URL
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            
            if test_case.get('remove_sig'):
                # Remove signature parameters
                for key in list(params.keys()):
                    if 'sig' in key.lower() or 'signature' in key.lower():
                        del params[key]
            else:
                # Modify signature parameter
                for key in list(params.keys()):
                    if 'sig' in key.lower() or 'signature' in key.lower():
                        params[key] = test_case.get('sig', params[key])
            
            # Reconstruct URL
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if params:
                test_url += '?' + urlencode(params, doseq=True)
            
            response = self._make_request(test_url)
            
            if response and response.status_code == 200:
                return self._check_authentication_success(response)
            
            return False
            
        except Exception as e:
            print(f"[!] Error testing signature manipulation: {str(e)}")
            return False
    
    def _test_timing_attacks(self):
        """Test for timing attack vulnerabilities in hash comparison"""
        print("[*] Testing for timing attacks...")
        
        try:
            # Get baseline timing
            baseline_times = []
            for _ in range(5):
                start = time.time()
                self._make_request(self.target)
                baseline_times.append(time.time() - start)
            
            avg_baseline = sum(baseline_times) / len(baseline_times)
            
            # Test with partially correct signatures
            test_signatures = [
                'a' * 32,  # All wrong
                'a' * 16 + 'b' * 16,  # Half potentially correct
                'correct_prefix' + 'a' * 16  # Correct prefix
            ]
            
            timings = []
            for sig in test_signatures:
                test_url = f"{self.target}{'&' if '?' in self.target else '?'}signature={sig}"
                
                sig_times = []
                for _ in range(5):
                    start = time.time()
                    self._make_request(test_url)
                    sig_times.append(time.time() - start)
                
                avg_time = sum(sig_times) / len(sig_times)
                timings.append(avg_time)
            
            # Check for timing differences
            if max(timings) - min(timings) > 0.1:  # 100ms difference
                self.vulnerabilities.append({
                    'type': 'Timing Attack',
                    'severity': 'medium',
                    'url': self.target,
                    'description': 'Hash comparison susceptible to timing attacks',
                    'impact': 'Attacker can deduce correct hash byte-by-byte',
                    'remediation': 'Use constant-time comparison functions',
                    'cwe': 'CWE-208',
                    'confidence': 70,
                    'timing_difference': f"{max(timings) - min(timings):.3f}s"
                })
                
        except Exception as e:
            print(f"[!] Error testing timing attacks: {str(e)}")
    
    def _test_hmac_vulnerabilities(self):
        """Test for HMAC implementation vulnerabilities"""
        print("[*] Testing for HMAC vulnerabilities...")
        
        test_cases = [
            # Weak HMAC algorithms
            {'algo': 'md5', 'severity': 'high'},
            {'algo': 'sha1', 'severity': 'medium'},
            
            # Short keys
            {'key_length': 8, 'severity': 'medium'},
            {'key_length': 16, 'severity': 'low'},
            
            # Key reuse across contexts
            {'test': 'key_reuse', 'severity': 'medium'}
        ]
        
        try:
            response = self._make_request(self.target)
            if not response:
                return
            
            # Check for HMAC indicators in response
            hmac_patterns = [
                r'hmac[_-]?(md5|sha1)',
                r'message[_-]?authentication[_-]?code',
                r'mac[_-]?algorithm'
            ]
            
            for pattern in hmac_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    algo = match.group(1) if match.lastindex else 'unknown'
                    
                    if algo in ['md5', 'sha1']:
                        self.vulnerabilities.append({
                            'type': 'Weak HMAC Algorithm',
                            'severity': 'medium',
                            'url': self.target,
                            'algorithm': algo.upper(),
                            'description': f'HMAC using weak algorithm: {algo.upper()}',
                            'impact': 'Reduced security of message authentication',
                            'remediation': 'Use HMAC-SHA256 or stronger',
                            'cwe': 'CWE-327',
                            'confidence': 65
                        })
                        
        except Exception as e:
            print(f"[!] Error testing HMAC vulnerabilities: {str(e)}")
    
    def _check_authentication_success(self, response) -> bool:
        """Check if authentication/authorization was successful"""
        # Success indicators
        success_patterns = [
            r'welcome', r'dashboard', r'logged[_\-]?in',
            r'authenticated', r'authorized', r'success'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        # Check for authentication tokens in response
        if 'Set-Cookie' in response.headers:
            cookies = response.headers['Set-Cookie']
            if any(token in cookies.lower() for token in ['session', 'auth', 'token']):
                return True
        
        return False
    
    def _make_request(self, url: str, method: str = 'GET', 
                     data: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with retry logic"""
        for attempt in range(self.max_retries):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        **kwargs
                    )
                else:
                    response = self.session.post(
                        url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        **kwargs
                    )
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    print(f"[!] Request failed after {self.max_retries} attempts: {str(e)}")
                    return None
                time.sleep(1)
        
        return None


# Example usage
if __name__ == "__main__":
    # Test configuration
    config = {
        'timeout': 15,
        'verify_ssl': False,
        'max_retries': 3
    }
    
    # Initialize scanner
    target = "https://example.com/api/verify"
    scanner = HashCollisionScanner(target, config)
    
    # Run scan
    vulnerabilities = scanner.scan()
    
    # Display results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"\n[{vuln['severity'].upper()}] {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Description: {vuln['description']}")
            print(f"Impact: {vuln['impact']}")
            print(f"Remediation: {vuln['remediation']}")
            print(f"Confidence: {vuln['confidence']}%")
    else:
        print("\n[+] No vulnerabilities found!")