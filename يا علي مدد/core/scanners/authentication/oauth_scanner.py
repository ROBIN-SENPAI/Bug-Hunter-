"""
OAuth Misconfiguration Scanner
كشف ثغرات تكوين OAuth
"""

import requests
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode
import json


class OAuthScanner:
    """ماسح ثغرات OAuth"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting OAuth Misconfiguration scan on: {self.target}")
        
        # 1. OAuth Endpoint Discovery
        endpoints = self._discover_oauth_endpoints()
        
        if not endpoints:
            print("  ⚠️  No OAuth endpoints found")
            return self.vulnerabilities
        
        print(f"  ✅ Found OAuth endpoints")
        
        # 2. Open Redirect in redirect_uri
        self._test_open_redirect(endpoints)
        
        # 3. State Parameter Missing/Weak
        self._test_state_parameter(endpoints)
        
        # 4. Token Leakage via Referer
        self._test_token_leakage(endpoints)
        
        # 5. Account Takeover via redirect_uri
        self._test_account_takeover(endpoints)
        
        # 6. Authorization Code Reuse
        self._test_code_reuse(endpoints)
        
        # 7. Client Secret Exposure
        self._test_client_secret_exposure()
        
        # 8. Implicit Flow Issues
        self._test_implicit_flow(endpoints)
        
        print(f"✅ Found {len(self.vulnerabilities)} OAuth vulnerabilities")
        return self.vulnerabilities
    
    def _discover_oauth_endpoints(self) -> Dict[str, str]:
        """اكتشاف OAuth Endpoints"""
        print("  📡 Discovering OAuth endpoints...")
        
        endpoints = {}
        
        try:
            response = self.session.get(self.target, timeout=10)
            text = response.text
            
            # البحث عن OAuth patterns
            oauth_patterns = {
                'authorize': r'(https?://[^"\'\s]+/oauth/authorize[^"\'\s]*)',
                'token': r'(https?://[^"\'\s]+/oauth/token[^"\'\s]*)',
                'login': r'(https?://[^"\'\s]+/oauth/login[^"\'\s]*)',
            }
            
            for endpoint_type, pattern in oauth_patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    endpoints[endpoint_type] = matches[0]
            
            # البحث في well-known URLs
            well_known_urls = [
                '/.well-known/openid-configuration',
                '/.well-known/oauth-authorization-server',
                '/oauth/authorize',
                '/oauth2/authorize',
                '/auth/oauth/authorize',
                '/api/oauth/authorize',
            ]
            
            for url in well_known_urls:
                try:
                    test_url = urljoin(self.target, url)
                    resp = self.session.get(test_url, timeout=5)
                    
                    if resp.status_code == 200:
                        if 'authorization_endpoint' in resp.text:
                            data = resp.json()
                            endpoints['authorize'] = data.get('authorization_endpoint', '')
                            endpoints['token'] = data.get('token_endpoint', '')
                            break
                except:
                    continue
            
            return endpoints
            
        except Exception as e:
            return {}
    
    def _test_open_redirect(self, endpoints: dict):
        """اختبار Open Redirect في redirect_uri"""
        print("  📡 Testing open redirect in redirect_uri...")
        
        if 'authorize' not in endpoints:
            return
        
        authorize_url = endpoints['authorize']
        
        # Payloads للـ redirect_uri
        redirect_payloads = [
            'https://evil.com',
            'https://evil.com/',
            'https://evil.com/callback',
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'https://evil.com@legitimate.com',
            'https://legitimate.com.evil.com',
        ]
        
        for payload in redirect_payloads:
            try:
                params = {
                    'response_type': 'code',
                    'client_id': 'test',
                    'redirect_uri': payload,
                    'scope': 'read',
                    'state': 'test123'
                }
                
                test_url = f"{authorize_url}?{urlencode(params)}"
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                # فحص إذا تم القبول
                if response.status_code in [200, 302, 303]:
                    location = response.headers.get('Location', '')
                    
                    if payload in location or response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'OAuth Misconfiguration',
                            'subtype': 'Open Redirect via redirect_uri',
                            'severity': 'high',
                            'url': test_url,
                            'redirect_payload': payload,
                            'confidence': 85,
                            'description': f'OAuth accepts arbitrary redirect_uri: {payload}',
                            'remediation': 'Whitelist allowed redirect_uri values'
                        })
                        print(f"    ✅ Open redirect found: {payload[:30]}...")
                        break
                        
            except Exception as e:
                continue
    
    def _test_state_parameter(self, endpoints: dict):
        """اختبار State Parameter"""
        print("  📡 Testing state parameter...")
        
        if 'authorize' not in endpoints:
            return
        
        authorize_url = endpoints['authorize']
        
        try:
            # بدون state parameter
            params = {
                'response_type': 'code',
                'client_id': 'test',
                'redirect_uri': 'https://example.com/callback',
                'scope': 'read'
            }
            
            test_url = f"{authorize_url}?{urlencode(params)}"
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            # إذا قبل الطلب بدون state
            if response.status_code in [200, 302]:
                self.vulnerabilities.append({
                    'type': 'OAuth Misconfiguration',
                    'subtype': 'Missing State Parameter',
                    'severity': 'medium',
                    'url': test_url,
                    'confidence': 80,
                    'description': 'OAuth endpoint accepts requests without state parameter (CSRF risk)',
                    'remediation': 'Make state parameter mandatory and validate it'
                })
                print("    ⚠️  State parameter not required")
            
            # اختبار state ضعيف
            weak_states = ['1', '123', 'test', 'state', '12345']
            
            for state in weak_states:
                params['state'] = state
                test_url = f"{authorize_url}?{urlencode(params)}"
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                if response.status_code in [200, 302]:
                    self.vulnerabilities.append({
                        'type': 'OAuth Misconfiguration',
                        'subtype': 'Weak State Parameter',
                        'severity': 'medium',
                        'url': test_url,
                        'state_value': state,
                        'confidence': 70,
                        'description': 'OAuth accepts predictable state values',
                        'remediation': 'Use cryptographically secure random state values'
                    })
                    print(f"    ⚠️  Weak state accepted: {state}")
                    break
                    
        except Exception as e:
            pass
    
    def _test_token_leakage(self, endpoints: dict):
        """اختبار تسريب Token عبر Referer"""
        print("  📡 Testing token leakage via referer...")
        
        if 'authorize' not in endpoints:
            return
        
        try:
            # استخدام implicit flow
            params = {
                'response_type': 'token',  # Implicit flow
                'client_id': 'test',
                'redirect_uri': 'https://evil.com',
                'scope': 'read',
                'state': 'test123'
            }
            
            authorize_url = endpoints['authorize']
            test_url = f"{authorize_url}?{urlencode(params)}"
            
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            if response.status_code in [302, 303]:
                location = response.headers.get('Location', '')
                
                # فحص إذا كان Token في URL
                if 'access_token=' in location:
                    self.vulnerabilities.append({
                        'type': 'OAuth Misconfiguration',
                        'subtype': 'Token Leakage via Referer',
                        'severity': 'high',
                        'url': test_url,
                        'confidence': 90,
                        'description': 'Access token exposed in URL (leaked via Referer header)',
                        'remediation': 'Use authorization code flow instead of implicit flow'
                    })
                    print("    ✅ Token leakage vulnerability found!")
                    
        except Exception as e:
            pass
    
    def _test_account_takeover(self, endpoints: dict):
        """اختبار Account Takeover"""
        print("  📡 Testing account takeover via redirect_uri...")
        
        if 'authorize' not in endpoints:
            return
        
        try:
            # محاولة تغيير redirect_uri لموقع المهاجم
            params = {
                'response_type': 'code',
                'client_id': 'legitimate_client',
                'redirect_uri': 'https://attacker.com/callback',
                'scope': 'profile email',
                'state': 'random123'
            }
            
            authorize_url = endpoints['authorize']
            test_url = f"{authorize_url}?{urlencode(params)}"
            
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            # إذا قبل redirect_uri المعدل
            if response.status_code in [200, 302]:
                location = response.headers.get('Location', '')
                
                if 'attacker.com' in location or 'code=' in location:
                    self.vulnerabilities.append({
                        'type': 'OAuth Misconfiguration',
                        'subtype': 'Account Takeover',
                        'severity': 'critical',
                        'url': test_url,
                        'confidence': 85,
                        'description': 'OAuth allows arbitrary redirect_uri, enabling account takeover',
                        'remediation': 'Strictly validate redirect_uri against whitelist'
                    })
                    print("    🔴 Account takeover vulnerability found!")
                    
        except Exception as e:
            pass
    
    def _test_code_reuse(self, endpoints: dict):
        """اختبار إعادة استخدام Authorization Code"""
        print("  📡 Testing authorization code reuse...")
        
        if 'token' not in endpoints:
            return
        
        # هذا الاختبار يتطلب authorization code حقيقي
        # سنتحقق فقط من وجود الـ endpoint
        
        try:
            token_url = endpoints['token']
            
            # محاولة استخدام code وهمي مرتين
            data = {
                'grant_type': 'authorization_code',
                'code': 'test_code_123',
                'client_id': 'test',
                'client_secret': 'test',
                'redirect_uri': 'https://example.com/callback'
            }
            
            # المحاولة الأولى
            response1 = self.session.post(token_url, data=data, timeout=10)
            
            # المحاولة الثانية بنفس الـ code
            response2 = self.session.post(token_url, data=data, timeout=10)
            
            # إذا نجحت المحاولة الثانية
            if response2.status_code == 200 and 'access_token' in response2.text:
                self.vulnerabilities.append({
                    'type': 'OAuth Misconfiguration',
                    'subtype': 'Authorization Code Reuse',
                    'severity': 'high',
                    'url': token_url,
                    'confidence': 75,
                    'description': 'Authorization codes can be reused multiple times',
                    'remediation': 'Invalidate authorization code after first use'
                })
                print("    ⚠️  Authorization code reuse possible")
                
        except Exception as e:
            pass
    
    def _test_client_secret_exposure(self):
        """اختبار تسريب Client Secret"""
        print("  📡 Testing client secret exposure...")
        
        try:
            response = self.session.get(self.target, timeout=10)
            text = response.text
            
            # البحث عن Client Secret patterns
            secret_patterns = [
                r'client_secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'CLIENT_SECRET["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'oauth_client_secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'api_secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in secret_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    for secret in matches:
                        if len(secret) > 10:  # تجاهل القيم القصيرة جداً
                            self.vulnerabilities.append({
                                'type': 'OAuth Misconfiguration',
                                'subtype': 'Client Secret Exposure',
                                'severity': 'critical',
                                'url': self.target,
                                'secret_snippet': secret[:10] + '...',
                                'confidence': 90,
                                'description': 'OAuth client secret exposed in client-side code',
                                'remediation': 'Never expose client secrets in frontend code'
                            })
                            print("    🔴 Client secret exposed!")
                            return
                            
        except Exception as e:
            pass
    
    def _test_implicit_flow(self, endpoints: dict):
        """اختبار Implicit Flow Issues"""
        print("  📡 Testing implicit flow security...")
        
        if 'authorize' not in endpoints:
            return
        
        try:
            params = {
                'response_type': 'token',
                'client_id': 'test',
                'redirect_uri': 'https://example.com/callback',
                'scope': 'read write',
                'state': 'test123'
            }
            
            authorize_url = endpoints['authorize']
            test_url = f"{authorize_url}?{urlencode(params)}"
            
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            if response.status_code in [200, 302]:
                self.vulnerabilities.append({
                    'type': 'OAuth Misconfiguration',
                    'subtype': 'Implicit Flow Enabled',
                    'severity': 'medium',
                    'url': test_url,
                    'confidence': 85,
                    'description': 'OAuth implicit flow is enabled (not recommended)',
                    'remediation': 'Use authorization code flow with PKCE instead'
                })
                print("    ⚠️  Implicit flow is enabled")
                
        except Exception as e:
            pass
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'OAuth Misconfiguration Scanner',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low']),
            }
        }


def urljoin(base: str, url: str) -> str:
    """دمج URLs"""
    from urllib.parse import urljoin as _urljoin
    return _urljoin(base, url)


if __name__ == "__main__":
    target = "http://example.com/oauth/authorize"
    scanner = OAuthScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 OAUTH SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
    print(f"Medium: {report['summary']['medium']}")
