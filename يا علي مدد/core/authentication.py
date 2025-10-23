"""
authentication.py
التعامل مع Authentication وجلسات المستخدم
"""

from typing import Dict, Optional
import base64
import hashlib
import hmac
import json


class Authentication:
    """معالج المصادقة"""
    
    def __init__(self):
        self.credentials = {}
        self.tokens = {}
        self.sessions = {}
    
    def set_basic_auth(self, username: str, password: str) -> Dict:
        """إعداد Basic Authentication"""
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        return {
            'Authorization': f'Basic {encoded}'
        }
    
    def set_bearer_token(self, token: str) -> Dict:
        """إعداد Bearer Token"""
        return {
            'Authorization': f'Bearer {token}'
        }
    
    def set_api_key(self, api_key: str, header_name: str = 'X-API-Key') -> Dict:
        """إعداد API Key"""
        return {
            header_name: api_key
        }
    
    def set_custom_auth(self, header_name: str, value: str) -> Dict:
        """إعداد مصادقة مخصصة"""
        return {
            header_name: value
        }
    
    def parse_jwt(self, token: str) -> Optional[Dict]:
        """تحليل JWT Token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # فك ترميز Header
            header = self._decode_jwt_part(parts[0])
            
            # فك ترميز Payload
            payload = self._decode_jwt_part(parts[1])
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except Exception as e:
            print(f"❌ JWT parsing error: {str(e)}")
            return None
    
    def _decode_jwt_part(self, part: str) -> Dict:
        """فك ترميز جزء من JWT"""
        # إضافة padding إذا لزم الأمر
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    
    def create_jwt_none_attack(self, payload: Dict) -> str:
        """إنشاء JWT مع None Algorithm Attack"""
        header = {
            'alg': 'none',
            'typ': 'JWT'
        }
        
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}."
    
    def test_jwt_vulnerabilities(self, token: str) -> Dict:
        """اختبار ثغرات JWT"""
        vulnerabilities = []
        
        parsed = self.parse_jwt(token)
        if not parsed:
            return {'vulnerable': False, 'issues': []}
        
        # التحقق من None Algorithm
        if parsed['header'].get('alg', '').lower() == 'none':
            vulnerabilities.append({
                'type': 'None Algorithm',
                'severity': 'critical',
                'description': 'JWT uses "none" algorithm'
            })
        
        # التحقق من Weak Secret
        if parsed['header'].get('alg', '').lower() in ['hs256', 'hs384', 'hs512']:
            vulnerabilities.append({
                'type': 'Weak Secret Possible',
                'severity': 'high',
                'description': 'JWT uses HMAC which might have weak secret'
            })
        
        # التحقق من معلومات حساسة في Payload
        sensitive_keys = ['password', 'secret', 'apikey', 'api_key']
        for key in sensitive_keys:
            if key in str(parsed['payload']).lower():
                vulnerabilities.append({
                    'type': 'Sensitive Data in Payload',
                    'severity': 'medium',
                    'description': f'Possible sensitive data: {key}'
                })
        
        return {
            'vulnerable': len(vulnerabilities) > 0,
            'issues': vulnerabilities,
            'parsed': parsed
        }
    
    def generate_hmac_signature(self, message: str, secret: str, algorithm: str = 'sha256') -> str:
        """توليد HMAC Signature"""
        if algorithm == 'sha256':
            return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        elif algorithm == 'sha1':
            return hmac.new(secret.encode(), message.encode(), hashlib.sha1).hexdigest()
        elif algorithm == 'md5':
            return hmac.new(secret.encode(), message.encode(), hashlib.md5).hexdigest()
        return ''
    
    def test_session_fixation(self, session_id: str) -> bool:
        """اختبار Session Fixation"""
        # يمكن استخدامه للتحقق من إمكانية تثبيت الجلسة
        if session_id in self.sessions:
            return True
        return False
    
    def store_credentials(self, username: str, password: str, service: str):
        """حفظ بيانات الاعتماد"""
        self.credentials[service] = {
            'username': username,
            'password': password
        }
    
    def get_credentials(self, service: str) -> Optional[Dict]:
        """الحصول على بيانات الاعتماد"""
        return self.credentials.get(service)
    
    def store_token(self, token: str, token_type: str = 'bearer'):
        """حفظ Token"""
        self.tokens[token_type] = token
    
    def get_token(self, token_type: str = 'bearer') -> Optional[str]:
        """الحصول على Token"""
        return self.tokens.get(token_type)