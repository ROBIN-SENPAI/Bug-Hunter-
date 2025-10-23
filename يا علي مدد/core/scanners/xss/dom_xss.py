"""
DOM-based XSS Scanner
====================
ماسح متقدم لاكتشاف ثغرات DOM XSS

Features:
- JavaScript source & sink detection
- Browser simulation with Selenium
- Client-side code analysis
- Dynamic payload testing
"""

import re
import time
from typing import List, Dict, Optional
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs, urljoin, quote

# Selenium imports (optional)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Selenium not available. DOM XSS detection will be limited.{Style.RESET_ALL}")


class DOMXSSScanner:
    """ماسح ثغرات DOM-based XSS"""
    
    def __init__(self, target_url: str, config: dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        self.use_selenium = config.get('use_selenium', SELENIUM_AVAILABLE)
        
        # DOM Sources (مصادر البيانات)
        self.dom_sources = [
            'location.href',
            'location.hash',
            'location.search',
            'document.URL',
            'document.documentURI',
            'document.referrer',
            'window.name',
            'document.cookie',
            'localStorage',
            'sessionStorage'
        ]
        
        # DOM Sinks (نقاط التنفيذ الخطرة)
        self.dom_sinks = [
            'eval',
            'innerHTML',
            'outerHTML',
            'document.write',
            'document.writeln',
            'setTimeout',
            'setInterval',
            'Function',
            'location.href',
            'location.assign',
            'location.replace',
            'script.src',
            'iframe.src',
            'embed.src',
            'object.data'
        ]
    
    def scan(self) -> List[Dict]:
        """فحص DOM XSS"""
        print(f"\n{Fore.CYAN}[*] Starting DOM-based XSS Scan...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Target: {self.target_url}{Style.RESET_ALL}")
        
        # 1. تحليل JavaScript الثابت
        print(f"\n{Fore.CYAN}[*] Analyzing JavaScript code...{Style.RESET_ALL}")
        js_vulns = self._analyze_javascript()
        
        # 2. اختبار ديناميكي مع Selenium
        if self.use_selenium:
            print(f"\n{Fore.CYAN}[*] Dynamic testing with browser...{Style.RESET_ALL}")
            dynamic_vulns = self._dynamic_testing()
            self.vulnerabilities.extend(dynamic_vulns)
        
        # 3. اختبار URL fragments
        print(f"\n{Fore.CYAN}[*] Testing URL fragments...{Style.RESET_ALL}")
        fragment_vulns = self._test_url_fragments()
        
        self.vulnerabilities.extend(js_vulns)
        self.vulnerabilities.extend(fragment_vulns)
        
        # النتائج
        self._print_results()
        return self.vulnerabilities
    
    def _analyze_javascript(self) -> List[Dict]:
        """تحليل كود JavaScript للبحث عن patterns خطرة"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. استخراج inline JavaScript
            inline_scripts = soup.find_all('script', src=False)
            
            for script in inline_scripts:
                js_code = script.string if script.string else ''
                vulns = self._analyze_js_code(js_code, 'inline')
                vulnerabilities.extend(vulns)
            
            # 2. استخراج external JavaScript files
            external_scripts = soup.find_all('script', src=True)
            
            for script in external_scripts:
                src = script.get('src', '')
                full_url = urljoin(self.target_url, src)
                
                try:
                    js_response = self.session.get(full_url, timeout=10)
                    vulns = self._analyze_js_code(js_response.text, full_url)
                    vulnerabilities.extend(vulns)
                except:
                    pass
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error analyzing JavaScript: {e}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _analyze_js_code(self, js_code: str, source: str) -> List[Dict]:
        """تحليل كود JavaScript للبحث عن Source → Sink patterns"""
        vulnerabilities = []
        
        # البحث عن patterns خطرة
        dangerous_patterns = [
            # location.hash → innerHTML
            {
                'pattern': r'(location\.hash|location\.search).*?(innerHTML|outerHTML)',
                'severity': 'High',
                'description': 'Direct assignment from URL to innerHTML'
            },
            # document.URL → eval
            {
                'pattern': r'(document\.URL|location\.href).*?eval',
                'severity': 'Critical',
                'description': 'URL content passed to eval()'
            },
            # location.hash → document.write
            {
                'pattern': r'location\.hash.*?document\.write',
                'severity': 'High',
                'description': 'URL hash used in document.write()'
            },
            # Unsafe jQuery
            {
                'pattern': r'\$\([\'"]#.*?[\'"]\)\.html\(location',
                'severity': 'High',
                'description': 'jQuery .html() with location data'
            },
            # setTimeout/setInterval with string
            {
                'pattern': r'(setTimeout|setInterval)\([\'"].*?location',
                'severity': 'High',
                'description': 'setTimeout/setInterval with URL data'
            }
        ]
        
        for pattern_info in dangerous_patterns:
            matches = re.finditer(pattern_info['pattern'], js_code, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                code_snippet = match.group(0)
                
                vuln = {
                    'type': 'DOM-based XSS',
                    'severity': pattern_info['severity'],
                    'source': source,
                    'description': pattern_info['description'],
                    'code_snippet': code_snippet[:100],
                    'confidence': 70,
                    'line': js_code[:match.start()].count('\n') + 1
                }
                vulnerabilities.append(vuln)
                
                print(f"{Fore.YELLOW}[!] Potential DOM XSS pattern found{Style.RESET_ALL}")
                print(f"    Pattern: {pattern_info['description']}")
                print(f"    Code: {code_snippet[:60]}...")
        
        return vulnerabilities
    
    def _dynamic_testing(self) -> List[Dict]:
        """اختبار ديناميكي باستخدام Selenium"""
        if not SELENIUM_AVAILABLE:
            return []
        
        vulnerabilities = []
        
        try:
            # إعداد Chrome headless
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            
            # Payloads للاختبار
            test_payloads = [
                '#<img src=x onerror=alert(1)>',
                '#<script>alert(1)</script>',
                '#"><svg/onload=alert(1)>',
                '?param=<img src=x onerror=alert(1)>',
            ]
            
            for payload in test_payloads:
                test_url = self.target_url + payload
                
                try:
                    driver.get(test_url)
                    time.sleep(2)
                    
                    # فحص alert dialogs
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        
                        # ثغرة مؤكدة!
                        vuln = {
                            'type': 'DOM-based XSS',
                            'severity': 'Critical',
                            'url': test_url,
                            'payload': payload,
                            'evidence': f'Alert triggered with text: {alert_text}',
                            'confidence': 95,
                            'verified': True
                        }
                        vulnerabilities.append(vuln)
                        
                        print(f"{Fore.RED}[!] DOM XSS CONFIRMED!{Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        
                    except:
                        # لا يوجد alert
                        pass
                    
                    # فحص الـ HTML للبحث عن payload
                    page_source = driver.page_source
                    if self._check_payload_execution(page_source, payload):
                        vuln = {
                            'type': 'DOM-based XSS',
                            'severity': 'High',
                            'url': test_url,
                            'payload': payload,
                            'evidence': 'Payload reflected in DOM',
                            'confidence': 80
                        }
                        vulnerabilities.append(vuln)
                
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing payload: {e}{Style.RESET_ALL}")
                    continue
            
            driver.quit()
        
        except Exception as e:
            print(f"{Fore.RED}[!] Selenium error: {e}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def _test_url_fragments(self) -> List[Dict]:
        """اختبار URL fragments (location.hash)"""
        vulnerabilities = []
        
        # Payloads خاصة بـ fragments
        payloads = [
            '#<script>alert(document.domain)</script>',
            '#<img src=x onerror=alert(1)>',
            '#"><svg/onload=alert(1)>',
            '#javascript:alert(1)',
            '#data:text/html,<script>alert(1)</script>',
        ]
        
        for payload in payloads:
            # هنا نحتاج تحليل ثابت فقط
            # لأن fragments لا تُرسل للسيرفر
            test_url = self.target_url + payload
            
            # فحص إذا كان الموقع يستخدم location.hash
            if self._site_uses_hash():
                vuln = {
                    'type': 'Potential DOM XSS',
                    'severity': 'Medium',
                    'url': test_url,
                    'payload': payload,
                    'description': 'Site uses location.hash - manual verification needed',
                    'confidence': 50,
                    'requires_verification': True
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _site_uses_hash(self) -> bool:
        """فحص إذا كان الموقع يستخدم location.hash"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # البحث عن استخدام location.hash في الكود
            hash_patterns = [
                r'location\.hash',
                r'window\.location\.hash',
                r'document\.location\.hash'
            ]
            
            for pattern in hash_patterns:
                if re.search(pattern, response.text):
                    return True
            
            return False
        except:
            return False
    
    def _check_payload_execution(self, html: str, payload: str) -> bool:
        """فحص تنفيذ الـ payload في DOM"""
        # إزالة # أو ?
        clean_payload = payload.lstrip('#?')
        
        # فحص وجود payload في HTML
        if clean_payload in html:
            # فحص إذا كان داخل script أو event handler
            dangerous_contexts = [
                f'<script>{clean_payload}',
                f'onerror={clean_payload}',
                f'onload={clean_payload}',
                f'<img src=x onerror={clean_payload}'
            ]
            
            for context in dangerous_contexts:
                if context in html:
                    return True
        
        return False
    
    def _print_results(self):
        """طباعة النتائج"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DOM-based XSS Scan Results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.RED}Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.RED}[{i}] {vuln['type']}{Style.RESET_ALL}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Confidence: {vuln.get('confidence', 'N/A')}%")
                
                if 'code_snippet' in vuln:
                    print(f"  Code: {vuln['code_snippet'][:60]}...")
                if 'payload' in vuln:
                    print(f"  Payload: {vuln['payload']}")
                if 'description' in vuln:
                    print(f"  Description: {vuln['description']}")
        else:
            print(f"\n{Fore.GREEN}[+] No DOM XSS vulnerabilities found{Style.RESET_ALL}")


if __name__ == "__main__":
    scanner = DOMXSSScanner(
        target_url="http://testphp.vulnweb.com/",
        config={'use_selenium': True}
    )
    
    results = scanner.scan()
    print(f"\nFound {len(results)} DOM XSS vulnerabilities")