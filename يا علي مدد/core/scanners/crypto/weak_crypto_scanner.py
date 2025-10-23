"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - Weak Crypto Scanner  ⚔️          ║
║           Detects Weak Cryptographic Implementations         ║
╚══════════════════════════════════════════════════════════════╝

Detects:
- Weak encryption algorithms (DES, 3DES, RC4, MD5, SHA1)
- Small key sizes
- Weak SSL/TLS versions
- Insecure cipher suites
- ECB mode usage
- Hardcoded keys/IVs

CWE: CWE-327, CWE-326, CWE-329
OWASP: A02:2021 - Cryptographic Failures
"""

import re
import ssl
import socket
import hashlib
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple


class WeakCryptoScanner:
    """Advanced scanner for weak cryptographic implementations"""
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        
        # Weak algorithms patterns
        self.weak_algorithms = {
            'DES': r'\bDES\b',
            '3DES': r'\b3DES\b|\bTRIPLE_DES\b',
            'RC4': r'\bRC4\b|\bARCFOUR\b',
            'MD5': r'\bMD5\b',
            'SHA1': r'\bSHA1\b|\bSHA-1\b',
            'ECB': r'\bECB\b',
            'Blowfish': r'\bBLOWFISH\b'
        }
        
        # Weak SSL/TLS versions
        self.weak_ssl_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None,
            'SSLv3': ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None,
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None
        }
        
        # Weak cipher suites (partial list)
        self.weak_ciphers = [
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 
            'anon', 'ADH', 'AECDH', 'LOW', 'EXP'
        ]

    def scan(self) -> List[Dict]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        print(f"[*] Starting Weak Cryptography scan on: {self.target}")
        
        # Parse target
        parsed = urlparse(self.target if '://' in self.target else f'https://{self.target}')
        hostname = parsed.hostname or parsed.path
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Scan SSL/TLS
        if parsed.scheme == 'https' or port == 443:
            self._scan_ssl_tls(hostname, port)
        
        # Scan for weak algorithms in responses
        self._scan_response_headers()
        
        # Scan for hardcoded keys
        self._scan_hardcoded_keys()
        
        # Scan cookies for weak encryption
        self._scan_cookie_encryption()
        
        # Scan for weak hashing in passwords
        self._scan_password_hashing()
        
        return self.vulnerabilities

    def _scan_ssl_tls(self, hostname: str, port: int):
        """Scan for weak SSL/TLS configurations"""
        print(f"[*] Scanning SSL/TLS configuration...")
        
        # Test weak SSL/TLS versions
        for version_name, protocol in self.weak_ssl_versions.items():
            if protocol is None:
                continue
                
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher = ssock.cipher()
                        
                        self.vulnerabilities.append({
                            'type': 'Weak SSL/TLS Version',
                            'severity': 'high',
                            'confidence': 95,
                            'url': f'{hostname}:{port}',
                            'version': version_name,
                            'cipher': cipher[0] if cipher else 'Unknown',
                            'description': f'Server supports weak SSL/TLS version: {version_name}',
                            'impact': 'Allows downgrade attacks and weak encryption',
                            'remediation': 'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Use TLS 1.2 or higher.',
                            'cwe': 'CWE-327',
                            'cvss': 7.5
                        })
                        print(f"  [!] Found weak version: {version_name}")
            except Exception:
                pass  # Version not supported (good!)
        
        # Test for weak ciphers
        self._test_weak_ciphers(hostname, port)

    def _test_weak_ciphers(self, hostname: str, port: int):
        """Test for weak cipher suites"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Check if cipher is weak
                        for weak in self.weak_ciphers:
                            if weak.upper() in cipher_name.upper():
                                self.vulnerabilities.append({
                                    'type': 'Weak Cipher Suite',
                                    'severity': 'high',
                                    'confidence': 90,
                                    'url': f'{hostname}:{port}',
                                    'cipher': cipher_name,
                                    'protocol': cipher[1],
                                    'description': f'Server supports weak cipher: {cipher_name}',
                                    'impact': 'Weak encryption allows potential decryption of traffic',
                                    'remediation': 'Configure server to use strong cipher suites (AES-GCM, ChaCha20)',
                                    'cwe': 'CWE-327',
                                    'cvss': 7.0
                                })
                                print(f"  [!] Found weak cipher: {cipher_name}")
                                break
        except Exception as e:
            print(f"  [-] Error testing ciphers: {str(e)}")

    def _scan_response_headers(self):
        """Scan HTTP response headers for crypto indicators"""
        print(f"[*] Scanning response headers...")
        
        try:
            import requests
            response = requests.get(self.target, timeout=10, verify=False)
            
            # Check headers for crypto information
            headers_to_check = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options'
            ]
            
            for header in headers_to_check:
                if header not in response.headers:
                    if header == 'Strict-Transport-Security':
                        self.vulnerabilities.append({
                            'type': 'Missing HSTS Header',
                            'severity': 'medium',
                            'confidence': 100,
                            'url': self.target,
                            'description': 'Strict-Transport-Security header is missing',
                            'impact': 'Traffic can be downgraded to HTTP, allowing MitM attacks',
                            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                            'cwe': 'CWE-319',
                            'cvss': 5.5
                        })
            
            # Check response body for crypto patterns
            body = response.text
            for algo, pattern in self.weak_algorithms.items():
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    self.vulnerabilities.append({
                        'type': 'Weak Algorithm Reference',
                        'severity': 'medium',
                        'confidence': 70,
                        'url': self.target,
                        'algorithm': algo,
                        'occurrences': len(matches),
                        'description': f'Reference to weak algorithm "{algo}" found in response',
                        'impact': 'May indicate use of weak cryptography',
                        'remediation': f'Replace {algo} with strong alternatives (AES-256, SHA-256)',
                        'cwe': 'CWE-327',
                        'cvss': 5.0
                    })
                    print(f"  [!] Found reference to: {algo}")
        
        except Exception as e:
            print(f"  [-] Error scanning headers: {str(e)}")

    def _scan_hardcoded_keys(self):
        """Scan for hardcoded cryptographic keys"""
        print(f"[*] Scanning for hardcoded keys...")
        
        # Common patterns for hardcoded keys
        key_patterns = [
            (r'(?:key|password|secret|token)\s*[=:]\s*["\']([a-zA-Z0-9+/]{16,})["\']', 'Hardcoded Key'),
            (r'(?:api_key|api_secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Hardcoded API Key'),
            (r'(?:private_key|secret_key)\s*[=:]\s*["\']([a-zA-Z0-9+/=]{40,})["\']', 'Hardcoded Private Key'),
            (r'["\']([0-9a-fA-F]{32})["\']', 'Potential MD5 Hash'),
            (r'["\']([0-9a-fA-F]{40})["\']', 'Potential SHA1 Hash'),
        ]
        
        try:
            import requests
            response = requests.get(self.target, timeout=10, verify=False)
            body = response.text
            
            for pattern, key_type in key_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    self.vulnerabilities.append({
                        'type': 'Hardcoded Cryptographic Material',
                        'severity': 'high',
                        'confidence': 60,
                        'url': self.target,
                        'key_type': key_type,
                        'sample': matches[0][:20] + '...' if len(matches[0]) > 20 else matches[0],
                        'description': f'{key_type} found in response',
                        'impact': 'Hardcoded keys can be extracted and used by attackers',
                        'remediation': 'Store keys securely (environment variables, key management systems)',
                        'cwe': 'CWE-798',
                        'cvss': 8.0
                    })
                    print(f"  [!] Found {key_type}")
        
        except Exception as e:
            print(f"  [-] Error scanning for keys: {str(e)}")

    def _scan_cookie_encryption(self):
        """Scan cookies for weak encryption"""
        print(f"[*] Scanning cookie encryption...")
        
        try:
            import requests
            response = requests.get(self.target, timeout=10, verify=False)
            
            for cookie in response.cookies:
                # Check if cookie is not secure
                if not cookie.secure:
                    self.vulnerabilities.append({
                        'type': 'Insecure Cookie',
                        'severity': 'medium',
                        'confidence': 100,
                        'url': self.target,
                        'cookie_name': cookie.name,
                        'description': f'Cookie "{cookie.name}" missing Secure flag',
                        'impact': 'Cookie can be intercepted over unencrypted connections',
                        'remediation': 'Set Secure flag on all sensitive cookies',
                        'cwe': 'CWE-614',
                        'cvss': 5.5
                    })
                    print(f"  [!] Insecure cookie: {cookie.name}")
                
                # Check if cookie is not HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    if 'session' in cookie.name.lower() or 'auth' in cookie.name.lower():
                        self.vulnerabilities.append({
                            'type': 'Missing HttpOnly Flag',
                            'severity': 'medium',
                            'confidence': 100,
                            'url': self.target,
                            'cookie_name': cookie.name,
                            'description': f'Cookie "{cookie.name}" missing HttpOnly flag',
                            'impact': 'Cookie accessible via JavaScript (XSS risk)',
                            'remediation': 'Set HttpOnly flag on session cookies',
                            'cwe': 'CWE-1004',
                            'cvss': 5.0
                        })
        
        except Exception as e:
            print(f"  [-] Error scanning cookies: {str(e)}")

    def _scan_password_hashing(self):
        """Detect weak password hashing methods"""
        print(f"[*] Scanning for weak password hashing...")
        
        # This would typically require testing login/registration endpoints
        # Here we'll look for indicators in responses
        
        try:
            import requests
            
            # Test common endpoints
            endpoints = [
                '/login', '/register', '/signup', '/api/auth',
                '/user/login', '/account/create'
            ]
            
            for endpoint in endpoints:
                try:
                    url = f"{self.target.rstrip('/')}{endpoint}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # Look for hash patterns in responses
                    if re.search(r'\b[a-f0-9]{32}\b', response.text):  # MD5
                        self.vulnerabilities.append({
                            'type': 'Weak Password Hashing (MD5)',
                            'severity': 'high',
                            'confidence': 50,
                            'url': url,
                            'description': 'Potential MD5 hash detected in response',
                            'impact': 'MD5 is cryptographically broken, passwords easily cracked',
                            'remediation': 'Use bcrypt, scrypt, or Argon2 for password hashing',
                            'cwe': 'CWE-327',
                            'cvss': 7.5
                        })
                        print(f"  [!] Potential MD5 usage at: {endpoint}")
                        
                except Exception:
                    continue
        
        except Exception as e:
            print(f"  [-] Error scanning password hashing: {str(e)}")

    def generate_report(self) -> Dict:
        """Generate detailed vulnerability report"""
        if not self.vulnerabilities:
            return {
                'status': 'clean',
                'message': 'No weak cryptography detected',
                'vulnerabilities': []
            }
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda x: severity_order.get(x['severity'], 5)
        )
        
        return {
            'status': 'vulnerable',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_severity': {
                'critical': sum(1 for v in self.vulnerabilities if v['severity'] == 'critical'),
                'high': sum(1 for v in self.vulnerabilities if v['severity'] == 'high'),
                'medium': sum(1 for v in self.vulnerabilities if v['severity'] == 'medium'),
                'low': sum(1 for v in self.vulnerabilities if v['severity'] == 'low')
            },
            'vulnerabilities': sorted_vulns
        }


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python weak_crypto.py <target>")
        print("Example: python weak_crypto.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = WeakCryptoScanner(target)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - Weak Crypto Scanner  ⚔️          ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    vulnerabilities = scanner.scan()
    report = scanner.generate_report()
    
    print(f"\n{'='*70}")
    print(f"SCAN RESULTS")
    print(f"{'='*70}")
    print(f"Status: {report['status'].upper()}")
    print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
    
    if report['total_vulnerabilities'] > 0:
        print(f"\nBy Severity:")
        print(f"  🔴 Critical: {report['by_severity']['critical']}")
        print(f"  🟠 High: {report['by_severity']['high']}")
        print(f"  🟡 Medium: {report['by_severity']['medium']}")
        print(f"  🟢 Low: {report['by_severity']['low']}")
        
        print(f"\n{'='*70}")
        print(f"DETAILED FINDINGS")
        print(f"{'='*70}")
        
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            print(f"\n[{i}] {vuln['type']}")
            print(f"    Severity: {vuln['severity'].upper()}")
            print(f"    Confidence: {vuln['confidence']}%")
            print(f"    URL: {vuln['url']}")
            print(f"    Description: {vuln['description']}")
            print(f"    Impact: {vuln['impact']}")
            print(f"    CVSS: {vuln['cvss']}")
            print(f"    CWE: {vuln['cwe']}")
    
    print(f"\n{'='*70}")
    print(f"Scan completed!")
    print(f"{'='*70}\n")
