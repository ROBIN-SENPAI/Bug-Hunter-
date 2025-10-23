"""
CORS Misconfiguration Scanner
كشف ثغرات تكوين CORS
"""

import requests
from typing import List, Dict, Optional


class CORSScanner:
    """ماسح ثغرات CORS"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting CORS Misconfiguration scan on: {self.target}")
        
        # 1. Wildcard Origin
        self._test_wildcard_origin()
        
        # 2. Null Origin
        self._test_null_origin()
        
        # 3. Arbitrary Origin Reflection
        self._test_origin_reflection()
        
        # 4. Subdomain Exploitation
        self._test_subdomain_bypass()
        
        # 5. Pre-domain Bypass
        self._test_predomain_bypass()
        
        # 6. Post-domain Bypass
        self._test_postdomain_bypass()
        
        # 7. Credentials Allowed
        self._test_credentials_allowed()
        
        # 8. Insecure Protocol
        self._test_insecure_protocol()
        
        print(f"✅ Found {len(self.vulnerabilities)} CORS vulnerabilities")
        return self.vulnerabilities
    
    def _test_wildcard_origin(self):
        """اختبار Wildcard Origin"""
        print("  📡 Testing wildcard origin...")
        
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Wildcard مع credentials
            if acao == '*' and acac.lower() == 'true':
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'subtype': 'Wildcard with Credentials',
                    'severity': 'critical',
                    'url': self.target,
                    'acao': acao,
                    'acac': acac,
                    'confidence': 95,
                    'description': 'CORS allows wildcard origin with credentials',
                    'remediation': 'Never use wildcard with credentials enabled'
                })
                print("    🔴 Wildcard with credentials!")
            
            # Wildcard فقط
            elif acao == '*':
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'subtype': 'Wildcard Origin',
                    'severity': 'medium',
                    'url': self.target,
                    'acao': acao,
                    'confidence': 85,
                    'description': 'CORS allows any origin (wildcard)',
                    'remediation': 'Specify allowed origins explicitly'
                })
                print("    ⚠️  Wildcard origin allowed")
                
        except Exception as e:
            pass
    
    def _test_null_origin(self):
        """اختبار Null Origin"""
        print("  📡 Testing null origin...")
        
        try:
            headers = {'Origin': 'null'}
            response = self.session.get(self.target, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao.lower() == 'null':
                severity = 'critical' if acac.lower() == 'true' else 'high'
                
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'subtype': 'Null Origin Allowed',
                    'severity': severity,
                    'url': self.target,
                    'acao': acao,
                    'acac': acac,
                    'confidence': 90,
                    'description': 'CORS accepts null origin (sandbox bypass)',
                    'remediation': 'Reject null origin explicitly'
                })
                print("    🔴 Null origin accepted!")
                
        except Exception as e:
            pass
    
    def _test_origin_reflection(self):
        """اختبار Origin Reflection"""
        print("  📡 Testing origin reflection...")
        
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'https://malicious.net',
            'http://evil.com',
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # إذا تم reflection الـ origin
                if acao == origin:
                    severity = 'critical' if acac.lower() == 'true' else 'high'
                    
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Arbitrary Origin Reflection',
                        'severity': severity,
                        'url': self.target,
                        'reflected_origin': origin,
                        'acao': acao,
                        'acac': acac,
                        'confidence': 95,
                        'description': 'CORS reflects any origin without validation',
                        'remediation': 'Validate origin against whitelist'
                    })
                    print(f"    🔴 Origin reflected: {origin}")
                    return
                    
            except Exception:
                continue
    
    def _test_subdomain_bypass(self):
        """اختبار Subdomain Bypass"""
        print("  📡 Testing subdomain bypass...")
        
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(self.target)
            domain = parsed.netloc
            
            # إزالة www إن وجد
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # توليد subdomains للاختبار
            test_subdomains = [
                f'evil.{domain}',
                f'attacker.{domain}',
                f'malicious.{domain}',
                f'test.{domain}',
            ]
            
            for subdomain in test_subdomains:
                headers = {'Origin': f'https://{subdomain}'}
                response = self.session.get(self.target, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if subdomain in acao:
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Subdomain Bypass',
                        'severity': 'high',
                        'url': self.target,
                        'subdomain': subdomain,
                        'acao': acao,
                        'acac': acac,
                        'confidence': 80,
                        'description': 'CORS allows arbitrary subdomains',
                        'remediation': 'Explicitly whitelist subdomains'
                    })
                    print(f"    ✅ Subdomain bypass: {subdomain}")
                    return
                    
        except Exception as e:
            pass
    
def _test_predomain_bypass(self):
    """اختبار Pre-domain Bypass"""
    print("  📡 Testing pre-domain bypass...")
    
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(self.target)
        domain = parsed.netloc
        
        # إضافة prefix قبل الدومين
        test_origins = [
            f'https://evil{domain}',
            f'https://attacker{domain}',
            f'https://{domain}.evil.com',
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            response = self.session.get(self.target, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == origin:
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'subtype': 'Pre-domain Bypass',
                    'severity': 'high',
                    'url': self.target,
                    'malicious_origin': origin,
                    'acao': acao,
                    'confidence': 75,
                    'description': 'CORS validation bypassable with pre-domain manipulation',
                    'remediation': 'Use strict domain validation'
                })
                print(f"    ✅ Pre-domain bypass: {origin}")
                return
                
    except Exception:
        pass  # أو يمكنك استخدام logging.error(e) إذا كنت تريد تسجيل الخطأ


def _test_postdomain_bypass(self):
    """اختبار Post-domain Bypass"""
    print("  📡 Testing post-domain bypass...")
    
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(self.target)
        domain = parsed.netloc
        
        # إضافة suffix بعد الدومين
        test_origins = [
            f'https://{domain}evil.com',
            f'https://{domain}.attacker.com',
            f'https://{domain}/evil.com',
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            response = self.session.get(self.target, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == origin:
                self.vulnerabilities.append({
                    'type': 'CORS Misconfiguration',
                    'subtype': 'Post-domain Bypass',
                    'severity': 'high',
                    'url': self.target,
                    'malicious_origin': origin,
                    'acao': acao,
                    'confidence': 75,
                    'description': 'CORS validation bypassable with post-domain manipulation',
                    'remediation': 'Validate domain boundaries properly'
                })
                print(f"    ✅ Post-domain bypass: {origin}")
                return
                
    except Exception:
        pass  # أو تسجيل الخطأ حسب الحاجة
    def _test_credentials_allowed(self):
        """اختبار Credentials Allowed"""
        print("  📡 Testing credentials allowed...")
        
        try:
            response = self.session.get(self.target, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # فحص إذا كانت credentials مفعلة
            if acac.lower() == 'true':
                # فحص إذا كان مع wildcard أو origin عشوائي
                if acao == '*':
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Credentials with Wildcard',
                        'severity': 'critical',
                        'url': self.target,
                        'acao': acao,
                        'acac': acac,
                        'confidence': 95,
                        'description': 'Credentials allowed with wildcard origin',
                        'remediation': 'Never allow credentials with wildcard'
                    })
                    print("    🔴 Credentials with wildcard!")
                else:
                    # مجرد تحذير
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Credentials Enabled',
                        'severity': 'info',
                        'url': self.target,
                        'acao': acao,
                        'acac': acac,
                        'confidence': 90,
                        'description': 'CORS allows credentials (ensure origin validation is strict)',
                        'remediation': 'Ensure origin whitelist is properly implemented'
                    })
                    print("    ℹ️  Credentials enabled")
                    
        except Exception as e:
            pass
    
    def _test_insecure_protocol(self):
        """اختبار Insecure Protocol"""
        print("  📡 Testing insecure protocol...")
        
        try:
            # محاولة HTTP origin على HTTPS target
            if self.target.startswith('https://'):
                headers = {'Origin': 'http://evil.com'}
                response = self.session.get(self.target, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao.startswith('http://'):
                    self.vulnerabilities.append({
                        'type': 'CORS Misconfiguration',
                        'subtype': 'Insecure Protocol Allowed',
                        'severity': 'high',
                        'url': self.target,
                        'acao': acao,
                        'confidence': 85,
                        'description': 'HTTPS endpoint allows HTTP origin (protocol downgrade)',
                        'remediation': 'Only allow HTTPS origins for HTTPS endpoints'
                    })
                    print("    ⚠️  HTTP origin allowed on HTTPS")
                    
        except Exception as e:
            pass
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'CORS Misconfiguration Scanner',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low']),
                'info': len([v for v in self.vulnerabilities if v['severity'] == 'info']),
            },
            'recommendations': [
                'Use a strict whitelist of allowed origins',
                'Never use wildcard (*) with credentials',
                'Reject null origin explicitly',
                'Validate origin format and boundaries',
                'Only allow HTTPS origins for HTTPS endpoints',
                'Implement proper subdomain validation'
            ]
        }


if __name__ == "__main__":
    target = "https://api.example.com/data"
    scanner = CORSScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 CORS SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
    print(f"Medium: {report['summary']['medium']}")
    print(f"Info: {report['summary'].get('info', 0)}")
    
    print("\n📋 Recommendations:")
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"  {i}. {rec}")