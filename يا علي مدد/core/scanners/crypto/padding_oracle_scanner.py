"""
╔══════════════════════════════════════════════════════════════╗
║       ⚔️  ALBATTAR BUGS - Padding Oracle Scanner  ⚔️         ║
║         Detects Padding Oracle Vulnerabilities (CBC)         ║
╚══════════════════════════════════════════════════════════════╝

Detects:
- Padding Oracle in CBC mode encryption
- Different error responses for padding errors
- Timing-based padding oracles
- Cookie/Token decryption via padding oracle

Attack Vector: Exploits padding validation errors in CBC mode
Impact: Allows decryption of encrypted data without knowing the key

CWE: CWE-326, CWE-203
CVE: CVE-2010-3864 (ASP.NET), CVE-2014-3566 (POODLE)
"""

import requests
import time
import base64
import binascii
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import statistics


class PaddingOracleScanner:
    """Advanced Padding Oracle vulnerability scanner"""
    
    def _scan_viewstate(self):
        """Scan ASP.NET ViewState for padding oracle"""
        print(f"[*] Scanning ViewState for padding oracle...")
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Look for ViewState in response
            import re
            viewstate_pattern = r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]+)"'
            matches = re.findall(viewstate_pattern, response.text)
            
            if matches:
                viewstate = matches[0]
                print(f"  [*] Testing ViewState")
                
                oracle_type = self._test_padding_oracle(
                    location='viewstate',
                    param_name='__VIEWSTATE',
                    original_value=viewstate
                )
                
                if oracle_type:
                    self.vulnerabilities.append({
                        'type': 'Padding Oracle Attack (ViewState)',
                        'severity': 'critical',
                        'confidence': 90,
                        'url': self.target,
                        'location': 'ASP.NET ViewState',
                        'parameter': '__VIEWSTATE',
                        'oracle_type': oracle_type,
                        'description': 'Padding oracle detected in ASP.NET ViewState',
                        'impact': 'ViewState can be decrypted and modified, leading to RCE',
                        'exploitation': self._generate_exploitation_steps('__VIEWSTATE', 'viewstate'),
                        'remediation': 'Upgrade .NET framework, enable ViewState MAC, use machineKey validation',
                        'cwe': 'CWE-326',
                        'cvss': 9.5,
                        'cve': 'CVE-2010-3864'
                    })
                    print(f"  [!] Critical ViewState padding oracle found!")
        
        except Exception as e:
            print(f"  [-] Error scanning ViewState: {str(e)}")

    def _test_padding_oracle(
        self,
        location: str,
        param_name: str,
        original_value: str
    ) -> Optional[str]:
        """
        Test for padding oracle vulnerability
        
        Returns:
            Oracle type if found ('error-based' or 'timing-based'), None otherwise
        """
        # Decode the encrypted value
        try:
            encrypted_bytes = base64.b64decode(original_value)
        except:
            try:
                encrypted_bytes = base64.urlsafe_b64decode(original_value + '==')
            except:
                return None
        
        # Must be at least 2 blocks (16 bytes each for AES)
        if len(encrypted_bytes) < 32:
            return None
        
        # Test 1: Error-based oracle
        error_oracle = self._test_error_based_oracle(
            location, param_name, original_value, encrypted_bytes
        )
        if error_oracle:
            return 'error-based'
        
        # Test 2: Timing-based oracle
        timing_oracle = self._test_timing_based_oracle(
            location, param_name, original_value, encrypted_bytes
        )
        if timing_oracle:
            return 'timing-based'
        
        return None

    def _test_error_based_oracle(
        self,
        location: str,
        param_name: str,
        original_value: str,
        encrypted_bytes: bytes
    ) -> bool:
        """Test for error-based padding oracle"""
        print(f"    [*] Testing error-based oracle...")
        
        # Make baseline request
        baseline_response = self._make_request(location, param_name, original_value)
        if not baseline_response:
            return False
        
        baseline_status = baseline_response.status_code
        baseline_length = len(baseline_response.content)
        baseline_text = baseline_response.text
        
        # Test with modified padding (flip last byte of second-to-last block)
        modified_bytes = bytearray(encrypted_bytes)
        modified_bytes[-17] ^= 0x01  # Flip one bit
        
        try:
            modified_value = base64.b64encode(bytes(modified_bytes)).decode()
        except:
            return False
        
        # Make request with modified padding
        modified_response = self._make_request(location, param_name, modified_value)
        if not modified_response:
            return False
        
        # Analyze differences
        status_diff = baseline_status != modified_response.status_code
        length_diff = abs(baseline_length - len(modified_response.content)) > 100
        
        # Check for padding error messages
        padding_errors = [
            'padding', 'invalid padding', 'pad block corrupted',
            'decryption error', 'bad decrypt', 'padding is invalid',
            'block size', 'cryptographic', 'cipher'
        ]
        
        text_diff = any(
            error in modified_response.text.lower() and error not in baseline_text.lower()
            for error in padding_errors
        )
        
        # Oracle detected if responses differ significantly
        if status_diff or length_diff or text_diff:
            print(f"    [!] Error-based oracle detected!")
            print(f"       Status: {baseline_status} -> {modified_response.status_code}")
            print(f"       Length: {baseline_length} -> {len(modified_response.content)}")
            return True
        
        return False

    def _test_timing_based_oracle(
        self,
        location: str,
        param_name: str,
        original_value: str,
        encrypted_bytes: bytes
    ) -> bool:
        """Test for timing-based padding oracle"""
        print(f"    [*] Testing timing-based oracle...")
        
        # Collect baseline timings (5 requests)
        baseline_timings = []
        for _ in range(5):
            start = time.time()
            response = self._make_request(location, param_name, original_value)
            if response:
                baseline_timings.append(time.time() - start)
            else:
                return False
        
        if len(baseline_timings) < 3:
            return False
        
        baseline_avg = statistics.mean(baseline_timings)
        baseline_stdev = statistics.stdev(baseline_timings) if len(baseline_timings) > 1 else 0
        
        # Test with modified padding
        modified_bytes = bytearray(encrypted_bytes)
        modified_bytes[-17] ^= 0x01
        
        try:
            modified_value = base64.b64encode(bytes(modified_bytes)).decode()
        except:
            return False
        
        # Collect modified timings (5 requests)
        modified_timings = []
        for _ in range(5):
            start = time.time()
            response = self._make_request(location, param_name, modified_value)
            if response:
                modified_timings.append(time.time() - start)
            else:
                return False
        
        if len(modified_timings) < 3:
            return False
        
        modified_avg = statistics.mean(modified_timings)
        
        # Check if timing difference is significant
        timing_diff = abs(baseline_avg - modified_avg)
        threshold = max(self.timing_threshold, baseline_stdev * 3)
        
        if timing_diff > threshold:
            print(f"    [!] Timing-based oracle detected!")
            print(f"       Baseline: {baseline_avg:.3f}s")
            print(f"       Modified: {modified_avg:.3f}s")
            print(f"       Difference: {timing_diff:.3f}s")
            return True
        
        return False

    def _make_request(
        self,
        location: str,
        param_name: str,
        value: str
    ) -> Optional[requests.Response]:
        """Make HTTP request with modified parameter"""
        self.request_count += 1
        
        if self.request_count > self.max_requests:
            print(f"  [!] Max requests reached ({self.max_requests})")
            return None
        
        try:
            if location == 'cookie':
                cookies = {param_name: value}
                response = self.session.get(
                    self.target,
                    cookies=cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            elif location == 'parameter':
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param_name] = [value]
                new_query = urlencode(params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                
                response = self.session.get(
                    new_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            elif location == 'header':
                headers = {param_name: f'Bearer {value}' if param_name == 'Authorization' else value}
                response = self.session.get(
                    self.target,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            elif location == 'viewstate':
                response = self.session.post(
                    self.target,
                    data={param_name: value},
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            else:
                return None
            
            return response
        
        except Exception as e:
            print(f"    [-] Request error: {str(e)}")
            return None

    def _is_encrypted_data(self, value: str) -> bool:
        """Check if value looks like encrypted/encoded data"""
        if len(value) < 16:
            return False
        
        # Check if Base64 encoded
        try:
            decoded = base64.b64decode(value)
            # Encrypted data should be at least 16 bytes and multiple of block size
            return len(decoded) >= 16 and len(decoded) % 8 == 0
        except:
            pass
        
        # Check URL-safe Base64
        try:
            decoded = base64.urlsafe_b64decode(value + '==')
            return len(decoded) >= 16 and len(decoded) % 8 == 0
        except:
            pass
        
        return False

    def _generate_exploitation_steps(self, param_name: str, location: str) -> List[str]:
        """Generate exploitation steps"""
        return [
            f"1. Identify the encrypted {location}: {param_name}",
            "2. Extract the encrypted value (Base64 encoded)",
            "3. Use padding oracle attack tool (e.g., PadBuster, padbuster.py)",
            "4. Decrypt the ciphertext block by block",
            "5. Modify plaintext and re-encrypt using the oracle",
            "6. Submit modified encrypted value to gain unauthorized access",
            "",
            "Example command:",
            f"padbuster {self.target} <encrypted_value> <block_size> -cookies {param_name}=<encrypted_value>"
        ]

    def generate_report(self) -> Dict:
        """Generate detailed vulnerability report"""
        if not self.vulnerabilities:
            return {
                'status': 'clean',
                'message': 'No padding oracle vulnerabilities detected',
                'vulnerabilities': []
            }
        
        return {
            'status': 'vulnerable',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'requests_made': self.request_count,
            'vulnerabilities': self.vulnerabilities,
            'risk_level': 'CRITICAL' if any(v['severity'] == 'critical' for v in self.vulnerabilities) else 'HIGH'
        }


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python padding_oracle.py <target>")
        print("Example: python padding_oracle.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = PaddingOracleScanner(target)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       ⚔️  ALBATTAR BUGS - Padding Oracle Scanner  ⚔️         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    vulnerabilities = scanner.scan()
    report = scanner.generate_report()
    
    print(f"\n{'='*70}")
    print(f"SCAN RESULTS")
    print(f"{'='*70}")
    print(f"Status: {report['status'].upper()}")
    print(f"Requests Made: {report.get('requests_made', 0)}")
    
    if report['status'] == 'vulnerable':
        print(f"Risk Level: {report['risk_level']}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        
        print(f"\n{'='*70}")
        print(f"DETAILED FINDINGS")
        print(f"{'='*70}")
        
        for i, vuln in enumerate(report['vulnerabilities'], 1):
            print(f"\n[{i}] {vuln['type']}")
            print(f"    Severity: {vuln['severity'].upper()}")
            print(f"    Location: {vuln['location']}")
            print(f"    Parameter: {vuln['parameter']}")
            print(f"    Oracle Type: {vuln['oracle_type']}")
            print(f"    Impact: {vuln['impact']}")
            print(f"    CVSS: {vuln['cvss']}")
    
    print(f"\n{'='*70}")
    print(f"Scan completed!")
    print(f"{'='*70}\n")
 __init__(self, target: str, config: Optional[Dict] = None):
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Configuration
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_requests = self.config.get('max_requests', 100)
        
        # Oracle detection thresholds
        self.timing_threshold = 0.5  # seconds
        self.error_detection_confidence = 80  # percentage
        
        # Request counter
        self.request_count = 0

    def scan(self) -> List[Dict]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        print(f"[*] Starting Padding Oracle scan on: {self.target}")
        
        # Scan for padding oracle in different locations
        self._scan_cookies()
        self._scan_parameters()
        self._scan_tokens()
        self._scan_viewstate()  # ASP.NET specific
        
        return self.vulnerabilities

    def _scan_cookies(self):
        """Scan cookies for padding oracle vulnerabilities"""
        print(f"[*] Scanning cookies for padding oracle...")
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            for cookie_name, cookie_value in response.cookies.items():
                # Check if cookie looks like encrypted data (Base64)
                if self._is_encrypted_data(cookie_value):
                    print(f"  [*] Testing cookie: {cookie_name}")
                    
                    oracle_type = self._test_padding_oracle(
                        location='cookie',
                        param_name=cookie_name,
                        original_value=cookie_value
                    )
                    
                    if oracle_type:
                        self.vulnerabilities.append({
                            'type': 'Padding Oracle Attack',
                            'severity': 'high',
                            'confidence': 85,
                            'url': self.target,
                            'location': 'Cookie',
                            'parameter': cookie_name,
                            'oracle_type': oracle_type,
                            'original_value': cookie_value[:50] + '...',
                            'description': f'Padding oracle detected in cookie "{cookie_name}"',
                            'impact': 'Attacker can decrypt cookie contents without knowing encryption key',
                            'exploitation': self._generate_exploitation_steps(cookie_name, 'cookie'),
                            'remediation': 'Use authenticated encryption (AES-GCM) or add HMAC validation',
                            'cwe': 'CWE-326',
                            'cvss': 7.5,
                            'references': [
                                'https://owasp.org/www-community/attacks/Padding_Oracle_attack',
                                'https://en.wikipedia.org/wiki/Padding_oracle_attack'
                            ]
                        })
                        print(f"  [!] Padding oracle found: {oracle_type}")
        
        except Exception as e:
            print(f"  [-] Error scanning cookies: {str(e)}")

    def _scan_parameters(self):
        """Scan URL/POST parameters for padding oracle"""
        print(f"[*] Scanning parameters for padding oracle...")
        
        try:
            # Parse URL parameters
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                param_value = param_values[0] if param_values else ''
                
                if self._is_encrypted_data(param_value):
                    print(f"  [*] Testing parameter: {param_name}")
                    
                    oracle_type = self._test_padding_oracle(
                        location='parameter',
                        param_name=param_name,
                        original_value=param_value
                    )
                    
                    if oracle_type:
                        self.vulnerabilities.append({
                            'type': 'Padding Oracle Attack',
                            'severity': 'high',
                            'confidence': 85,
                            'url': self.target,
                            'location': 'GET Parameter',
                            'parameter': param_name,
                            'oracle_type': oracle_type,
                            'description': f'Padding oracle detected in parameter "{param_name}"',
                            'impact': 'Attacker can decrypt parameter value without encryption key',
                            'exploitation': self._generate_exploitation_steps(param_name, 'parameter'),
                            'remediation': 'Use authenticated encryption or HMAC validation',
                            'cwe': 'CWE-326',
                            'cvss': 7.5
                        })
                        print(f"  [!] Padding oracle found: {oracle_type}")
        
        except Exception as e:
            print(f"  [-] Error scanning parameters: {str(e)}")

    def _scan_tokens(self):
        """Scan authentication tokens for padding oracle"""
        print(f"[*] Scanning tokens for padding oracle...")
        
        token_headers = [
            'Authorization',
            'X-Auth-Token',
            'X-API-Key',
            'X-Session-Token'
        ]
        
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            for header in token_headers:
                if header in response.request.headers:
                    token_value = response.request.headers[header]
                    
                    # Remove "Bearer " prefix if present
                    if token_value.startswith('Bearer '):
                        token_value = token_value[7:]
                    
                    if self._is_encrypted_data(token_value):
                        print(f"  [*] Testing header: {header}")
                        
                        oracle_type = self._test_padding_oracle(
                            location='header',
                            param_name=header,
                            original_value=token_value
                        )
                        
                        if oracle_type:
                            self.vulnerabilities.append({
                                'type': 'Padding Oracle Attack',
                                'severity': 'critical',
                                'confidence': 85,
                                'url': self.target,
                                'location': 'Header',
                                'parameter': header,
                                'oracle_type': oracle_type,
                                'description': f'Padding oracle detected in {header} header',
                                'impact': 'Authentication token can be decrypted, leading to account takeover',
                                'exploitation': self._generate_exploitation_steps(header, 'header'),
                                'remediation': 'Use JWT with proper signature or authenticated encryption',
                                'cwe': 'CWE-326',
                                'cvss': 9.0
                            })
                            print(f"  [!] Critical padding oracle found in token!")
        
        except Exception as e:
            print(f"  [-] Error scanning tokens: {str(e)}")

    def