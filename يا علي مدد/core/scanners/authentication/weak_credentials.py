"""
Weak Credentials Scanner
كشف كلمات المرور الضعيفة والافتراضية
"""

import requests
import itertools
from typing import List, Dict, Optional
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class WeakCredentialsScanner:
    """ماسح كلمات المرور الضعيفة"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        self.found_credentials = []
        
        # قائمة أسماء المستخدمين الشائعة
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'webmaster', 'sa', 'operator',
            'supervisor', 'manager', 'sysadmin', 'system',
            'default', 'support', 'helpdesk', 'backup'
        ]
        
        # قائمة كلمات المرور الضعيفة
        self.weak_passwords = [
            '', 'password', 'Password', 'PASSWORD',
            '123456', '12345678', '123456789', 'qwerty',
            'abc123', 'password123', 'admin', 'Admin',
            'admin123', 'root', 'pass', 'test', 'Test',
            '1234', '12345', '123', '1234567890',
            'welcome', 'Welcome', 'letmein', 'monkey',
            'dragon', 'master', 'password1', 'Password1',
            'p@ssw0rd', 'P@ssw0rd', 'P@ssword', 'passw0rd'
        ]
        
        # كلمات مرور افتراضية حسب النظام/التطبيق
        self.default_credentials = [
            # Format: (username, password, system)
            ('admin', 'admin', 'Generic'),
            ('administrator', 'administrator', 'Generic'),
            ('root', 'root', 'Generic'),
            ('root', 'toor', 'Linux'),
            ('admin', 'password', 'Generic'),
            ('admin', '1234', 'Generic'),
            ('admin', '12345', 'Generic'),
            ('admin', '', 'Generic'),
            ('admin', 'admin123', 'Generic'),
            
            # Database defaults
            ('root', '', 'MySQL'),
            ('root', 'mysql', 'MySQL'),
            ('admin', 'admin', 'MySQL'),
            ('postgres', 'postgres', 'PostgreSQL'),
            ('sa', '', 'MSSQL'),
            ('sa', 'sa', 'MSSQL'),
            
            # Router/Network devices
            ('admin', 'admin', 'Router'),
            ('admin', '1234', 'Router'),
            ('user', 'user', 'Router'),
            ('cisco', 'cisco', 'Cisco'),
            ('admin', 'password', 'D-Link'),
            ('admin', '', 'Netgear'),
            
            # Web applications
            ('admin', 'admin', 'WordPress'),
            ('admin', 'password', 'Joomla'),
            ('admin', 'admin123', 'Drupal'),
            ('administrator', 'admin', 'Magento'),
            
            # IoT/Cameras
            ('admin', '12345', 'Camera'),
            ('admin', '888888', 'Camera'),
            ('admin', '666666', 'Camera'),
            ('root', '12345', 'DVR'),
            ('admin', 'admin123', 'NVR'),
        ]
        
        self.max_threads = config.get('max_threads', 5)
        self.timeout = config.get('timeout', 10)
        self.delay = config.get('delay', 0.5)
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting Weak Credentials scan on: {self.target}")
        
        # 1. فحص الاعتمادات الافتراضية
        print("  📡 Testing default credentials...")
        self._test_default_credentials()
        
        # 2. فحص كلمات المرور الضعيفة
        print("  📡 Testing weak passwords...")
        self._test_weak_passwords()
        
        # 3. فحص كلمات المرور المبنية على اسم الموقع
        print("  📡 Testing domain-based passwords...")
        self._test_domain_passwords()
        
        print(f"✅ Found {len(self.found_credentials)} valid credentials")
        return self.vulnerabilities
    
    def _test_default_credentials(self):
        """اختبار الاعتمادات الافتراضية"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for username, password, system in self.default_credentials:
                future = executor.submit(
                    self._attempt_login,
                    username,
                    password,
                    f'Default ({system})'
                )
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found_credentials.append(result)
                time.sleep(self.delay)
    
    def _test_weak_passwords(self):
        """اختبار كلمات المرور الضعيفة"""
        combinations = list(itertools.product(
            self.common_usernames[:10],  # أول 10 مستخدمين
            self.weak_passwords[:15]     # أول 15 كلمة مرور
        ))
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for username, password in combinations:
                future = executor.submit(
                    self._attempt_login,
                    username,
                    password,
                    'Weak Password'
                )
                futures.append(future)
            
            completed = 0
            total = len(combinations)
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found_credentials.append(result)
                completed += 1
                
                if completed % 10 == 0:
                    print(f"    Progress: {completed}/{total} attempts")
                
                time.sleep(self.delay)
    
    def _test_domain_passwords(self):
        """اختبار كلمات مرور مبنية على اسم النطاق"""
        from urllib.parse import urlparse
        
        domain = urlparse(self.target).netloc
        domain_parts = domain.split('.')
        
        # استخراج اسم الشركة
        company_name = domain_parts[0] if len(domain_parts) > 0 else 'company'
        
        # توليد كلمات مرور محتملة
        domain_passwords = [
            company_name,
            company_name.capitalize(),
            company_name.upper(),
            f'{company_name}123',
            f'{company_name}2024',
            f'{company_name}2025',
            f'{company_name}@123',
            f'{company_name}!',
            f'Welcome{company_name}',
            f'{company_name}admin',
        ]
        
        for username in ['admin', 'administrator', company_name]:
            for password in domain_passwords:
                result = self._attempt_login(username, password, 'Domain-based')
                if result:
                    self.found_credentials.append(result)
                time.sleep(self.delay)
    
    def _attempt_login(self, username: str, password: str, type: str) -> Optional[Dict]:
        """محاولة تسجيل الدخول"""
        try:
            # تجربة POST
            data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'email': username,
                'login': 'Login',
                'submit': 'Submit'
            }
            
            response = self.session.post(
                self.target,
                data=data,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            if self._is_login_successful(response):
                vuln = {
                    'type': 'Weak Credentials',
                    'subtype': type,
                    'severity': 'critical',
                    'url': self.target,
                    'username': username,
                    'password': password,
                    'confidence': 95,
                    'evidence': {
                        'status_code': response.status_code,
                        'redirect': response.headers.get('Location', ''),
                        'cookies': dict(response.cookies)
                    },
                    'description': f'Valid credentials found: {username}:{password}',
                    'remediation': 'Change to strong, unique password immediately'
                }
                
                self.vulnerabilities.append(vuln)
                print(f"    ✅ Valid credentials: {username}:{password}")
                return vuln
            
            return None
            
        except Exception as e:
            return None
    
    def _is_login_successful(self, response) -> bool:
        """التحقق من نجاح تسجيل الدخول"""
        # مؤشرات النجاح
        success_indicators = [
            'dashboard', 'welcome', 'profile', 'logout',
            'admin panel', 'administration', 'settings',
            'successfully logged', 'login successful',
            'welcome back', 'my account'
        ]
        
        # مؤشرات الفشل
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error',
            'wrong', 'denied', 'authentication failed',
            'login failed', 'bad credentials'
        ]
        
        # Status codes
        if response.status_code in [200, 301, 302, 303]:
            text_lower = response.text.lower()
            
            # التحقق من الـ redirect
            location = response.headers.get('Location', '').lower()
            if any(indicator in location for indicator in ['dashboard', 'admin', 'panel', 'home', 'profile']):
                return True
            
            # التحقق من وجود session cookie
            if 'set-cookie' in response.headers:
                cookies = response.headers.get('set-cookie', '').lower()
                if any(word in cookies for word in ['session', 'auth', 'token', 'logged']):
                    if not any(fail in text_lower for fail in failure_indicators):
                        return True
            
            # التحقق من المحتوى
            if any(indicator in text_lower for indicator in success_indicators):
                if not any(fail in text_lower for fail in failure_indicators):
                    return True
        
        return False
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'Weak Credentials Scanner',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'found_credentials': self.found_credentials,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
            }
        }


if __name__ == "__main__":
    target = "http://testphp.vulnweb.com/login.php"
    scanner = WeakCredentialsScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nFound Credentials: {len(report['found_credentials'])}")
            