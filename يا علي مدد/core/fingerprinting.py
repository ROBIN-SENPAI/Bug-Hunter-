"""
fingerprinting.py
بصمة التقنيات المستخدمة (Technology Fingerprinting)
"""

import re
from typing import Dict, List, Optional
import requests


class Fingerprinting:
    """كشف التقنيات المستخدمة في الموقع"""
    
    def __init__(self):
        self.detected_technologies = {
            'server': None,
            'backend': [],
            'frontend': [],
            'frameworks': [],
            'databases': [],
            'cms': None,
            'cdn': None,
            'waf': None,
            'analytics': [],
            'javascript_libraries': []
        }
        
        # تواقيع التقنيات
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict:
        """تحميل تواقيع التقنيات"""
        return {
            'servers': {
                'Apache': [r'Apache/[\d.]+', 'Server: Apache'],
                'Nginx': [r'nginx/[\d.]+', 'Server: nginx'],
                'IIS': [r'Microsoft-IIS/[\d.]+', 'Server: Microsoft-IIS'],
                'LiteSpeed': [r'LiteSpeed', 'Server: LiteSpeed'],
                'Cloudflare': ['Server: cloudflare', 'CF-Ray']
            },
            'languages': {
                'PHP': [r'X-Powered-By: PHP/[\d.]+', '.php', 'PHPSESSID'],
                'ASP.NET': [r'X-Powered-By: ASP\.NET', 'ASPSESSIONID', '.aspx'],
                'Python': ['X-Powered-By: Python', '.py'],
                'Ruby': ['X-Powered-By: Phusion Passenger', '.rb'],
                'Node.js': ['X-Powered-By: Express', 'connect.sid'],
                'Java': ['JSESSIONID', '.jsp', '.do']
            },
            'frameworks': {
                'Laravel': ['laravel_session', 'XSRF-TOKEN'],
                'Django': ['csrftoken', 'sessionid', '__django'],
                'Express': ['connect.sid'],
                'Spring': ['JSESSIONID', 'spring'],
                'Rails': ['_rails_session', '_session_id']
            },
            'cms': {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
                'Joomla': ['/components/com_', '/modules/mod_'],
                'Drupal': ['/sites/default/', 'Drupal'],
                'Magento': ['/skin/frontend/', 'Mage.'],
                'Shopify': ['cdn.shopify.com', '.myshopify.com']
            },
            'databases': {
                'MySQL': ['mysql', 'mysqli'],
                'PostgreSQL': ['postgres', 'pgsql'],
                'MongoDB': ['mongodb'],
                'MSSQL': ['mssql', 'sqlserver'],
                'Oracle': ['oracle']
            },
            'waf': {
                'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
                'ModSecurity': ['mod_security', 'NOYB'],
                'Imperva': ['incap_ses', 'visid_incap'],
                'Sucuri': ['sucuri', 'X-Sucuri'],
                'Akamai': ['akamai', 'AkamaiGHost']
            },
            'javascript': {
                'jQuery': ['jquery', 'jQuery'],
                'React': ['react', '_reactRoot'],
                'Vue.js': ['vue', '__vue__'],
                'Angular': ['ng-', 'angular'],
                'Bootstrap': ['bootstrap'],
                'Tailwind': ['tailwindcss']
            }
        }
    
    def fingerprint(self, url: str, response: requests.Response = None) -> Dict:
        """بصمة الموقع بالكامل"""
        if not response:
            try:
                response = requests.get(url, timeout=10, verify=False)
            except:
                return self.detected_technologies
        
        # كشف من Headers
        self._detect_from_headers(response.headers)
        
        # كشف من المحتوى
        self._detect_from_content(response.text)
        
        # كشف من Cookies
        self._detect_from_cookies(response.cookies)
        
        return self.detected_technologies
    
    def _detect_from_headers(self, headers: Dict):
        """كشف من HTTP Headers"""
        headers_str = str(headers).lower()
        
        # كشف السيرفر
        server = headers.get('Server', '')
        if server:
            for tech, patterns in self.signatures['servers'].items():
                for pattern in patterns:
                    if re.search(pattern, server, re.IGNORECASE):
                        self.detected_technologies['server'] = tech
                        break
        
        # كشف اللغة
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            for lang, patterns in self.signatures['languages'].items():
                for pattern in patterns:
                    if re.search(pattern, powered_by, re.IGNORECASE):
                        if lang not in self.detected_technologies['backend']:
                            self.detected_technologies['backend'].append(lang)
        
        # كشف WAF
        for waf, patterns in self.signatures['waf'].items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    self.detected_technologies['waf'] = waf
                    break
        
        # كشف CDN
        cdn_headers = ['cf-ray', 'x-amz-cf-id', 'x-cdn', 'via']
        for header in cdn_headers:
            if header in headers_str:
                if 'cloudflare' in headers_str or 'cf-ray' in headers_str:
                    self.detected_technologies['cdn'] = 'Cloudflare'
                elif 'akamai' in headers_str:
                    self.detected_technologies['cdn'] = 'Akamai'
                elif 'fastly' in headers_str:
                    self.detected_technologies['cdn'] = 'Fastly'
    
    def _detect_from_content(self, content: str):
        """كشف من محتوى الصفحة"""
        content_lower = content.lower()
        
        # كشف CMS
        for cms, patterns in self.signatures['cms'].items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    self.detected_technologies['cms'] = cms
                    break
        
        # كشف JavaScript Libraries
        for js_lib, patterns in self.signatures['javascript'].items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    if js_lib not in self.detected_technologies['javascript_libraries']:
                        self.detected_technologies['javascript_libraries'].append(js_lib)
        
        # كشف Frameworks
        for framework, patterns in self.signatures['frameworks'].items():
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    if framework not in self.detected_technologies['frameworks']:
                        self.detected_technologies['frameworks'].append(framework)
        
        # كشف Meta Tags
        meta_patterns = {
            'generator': r'<meta name="generator" content="([^"]+)"',
            'application-name': r'<meta name="application-name" content="([^"]+)"'
        }
        
        for meta_name, pattern in meta_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                generator = match.group(1)
                if 'wordpress' in generator.lower():
                    self.detected_technologies['cms'] = 'WordPress'
                elif 'drupal' in generator.lower():
                    self.detected_technologies['cms'] = 'Drupal'
                elif 'joomla' in generator.lower():
                    self.detected_technologies['cms'] = 'Joomla'
    
    def _detect_from_cookies(self, cookies):
        """كشف من Cookies"""
        cookie_names = [cookie.name.lower() for cookie in cookies]
        
        # كشف اللغة من Cookies
        for lang, patterns in self.signatures['languages'].items():
            for pattern in patterns:
                if any(pattern.lower() in cookie_name for cookie_name in cookie_names):
                    if lang not in self.detected_technologies['backend']:
                        self.detected_technologies['backend'].append(lang)
        
        # كشف Frameworks
        for framework, patterns in self.signatures['frameworks'].items():
            for pattern in patterns:
                if any(pattern.lower() in cookie_name for cookie_name in cookie_names):
                    if framework not in self.detected_technologies['frameworks']:
                        self.detected_technologies['frameworks'].append(framework)
    
    def get_summary(self) -> str:
        """الحصول على ملخص التقنيات"""
        summary = []
        
        if self.detected_technologies['server']:
            summary.append(f"Server: {self.detected_technologies['server']}")
        
        if self.detected_technologies['backend']:
            summary.append(f"Backend: {', '.join(self.detected_technologies['backend'])}")
        
        if self.detected_technologies['frameworks']:
            summary.append(f"Frameworks: {', '.join(self.detected_technologies['frameworks'])}")
        
        if self.detected_technologies['cms']:
            summary.append(f"CMS: {self.detected_technologies['cms']}")
        
        if self.detected_technologies['waf']:
            summary.append(f"WAF: {self.detected_technologies['waf']}")
        
        if self.detected_technologies['cdn']:
            summary.append(f"CDN: {self.detected_technologies['cdn']}")
        
        if self.detected_technologies['javascript_libraries']:
            summary.append(f"JS Libraries: {', '.join(self.detected_technologies['javascript_libraries'])}")
        
        return '\n'.join(summary) if summary else 'No technologies detected'
    
    def print_results(self):
        """طباعة النتائج بشكل منسق"""
        print("\n" + "="*70)
        print("🔍 TECHNOLOGY FINGERPRINTING RESULTS")
        print("="*70)
        
        print("\n📡 SERVER INFORMATION:")
        print(f"  Server: {self.detected_technologies['server'] or 'Unknown'}")
        print(f"  WAF: {self.detected_technologies['waf'] or 'None detected'}")
        print(f"  CDN: {self.detected_technologies['cdn'] or 'None detected'}")
        
        print("\n💻 BACKEND TECHNOLOGIES:")
        if self.detected_technologies['backend']:
            for tech in self.detected_technologies['backend']:
                print(f"  • {tech}")
        else:
            print("  None detected")
        
        print("\n🎨 FRONTEND TECHNOLOGIES:")
        if self.detected_technologies['javascript_libraries']:
            for lib in self.detected_technologies['javascript_libraries']:
                print(f"  • {lib}")
        else:
            print("  None detected")
        
        print("\n🚀 FRAMEWORKS:")
        if self.detected_technologies['frameworks']:
            for fw in self.detected_technologies['frameworks']:
                print(f"  • {fw}")
        else:
            print("  None detected")
        
        print("\n📝 CMS:")
        print(f"  {self.detected_technologies['cms'] or 'None detected'}")
        
        print("\n" + "="*70 + "\n")