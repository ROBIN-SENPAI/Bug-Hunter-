"""
payload_encoder.py
ترميز الـ Payloads (Base64, URL, Unicode, etc)
"""

import base64
import urllib.parse
import html
from typing import List


class PayloadEncoder:
    """ترميز متقدم للـ Payloads"""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """ترميز URL عادي"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """ترميز URL مزدوج"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """ترميز Base64"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def html_encode(payload: str) -> str:
        """ترميز HTML"""
        return html.escape(payload)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """ترميز Unicode"""
        return ''.join(f'\\u{ord(char):04x}' for char in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """ترميز Hexadecimal"""
        return ''.join(f'\\x{ord(char):02x}' for char in payload)
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """ترميز Octal"""
        return ''.join(f'\\{ord(char):03o}' for char in payload)
    
    @staticmethod
    def utf7_encode(payload: str) -> str:
        """ترميز UTF-7"""
        try:
            return payload.encode('utf-7').decode('ascii')
        except:
            return payload
    
    @staticmethod
    def case_variation(payload: str) -> List[str]:
        """تغيير حالة الأحرف"""
        variations = [
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
            payload.title()
        ]
        return variations
    
    @staticmethod
    def comment_insertion(payload: str) -> List[str]:
        """إدراج تعليقات (للـ SQL)"""
        variations = [
            payload.replace(' ', '/**/'),
            payload.replace(' ', '/**_**/'),
            payload.replace(' ', '/*--*/'),
        ]
        return variations
    
    @staticmethod
    def null_byte_injection(payload: str) -> str:
        """إضافة Null Byte"""
        return payload + '%00'
    
    @staticmethod
    def newline_injection(payload: str) -> List[str]:
        """إضافة أسطر جديدة"""
        return [
            payload + '%0a',
            payload + '%0d',
            payload + '%0d%0a',
            payload + '\n',
            payload + '\r',
            payload + '\r\n'
        ]
    
    @staticmethod
    def space_replacement(payload: str) -> List[str]:
        """استبدال المسافات"""
        replacements = [
            payload.replace(' ', '+'),
            payload.replace(' ', '%20'),
            payload.replace(' ', '%09'),  # Tab
            payload.replace(' ', '%0b'),  # Vertical Tab
            payload.replace(' ', '/**/'),  # للـ SQL
        ]
        return replacements
    
    @staticmethod
    def mixed_encoding(payload: str) -> List[str]:
        """ترميز مختلط"""
        encoder = PayloadEncoder()
        return [
            encoder.url_encode(payload),
            encoder.double_url_encode(payload),
            encoder.base64_encode(payload),
            encoder.hex_encode(payload),
            encoder.unicode_encode(payload),
        ]
    
    @staticmethod
    def waf_bypass_techniques(payload: str) -> List[str]:
        """تقنيات تجاوز WAF"""
        techniques = []
        encoder = PayloadEncoder()
        
        # Case variations
        techniques.extend(encoder.case_variation(payload))
        
        # Space replacements
        techniques.extend(encoder.space_replacement(payload))
        
        # Comment insertions
        techniques.extend(encoder.comment_insertion(payload))
        
        # Encodings
        techniques.append(encoder.url_encode(payload))
        techniques.append(encoder.double_url_encode(payload))
        
        # Null byte
        techniques.append(encoder.null_byte_injection(payload))
        
        return list(set(techniques))  # إزالة المكررات
    
    def encode_payload(self, payload: str, encoding_type: str) -> str:
        """ترميز payload بنوع محدد"""
        encoders = {
            'url': self.url_encode,
            'double_url': self.double_url_encode,
            'base64': self.base64_encode,
            'html': self.html_encode,
            'unicode': self.unicode_encode,
            'hex': self.hex_encode,
            'octal': self.octal_encode,
            'utf7': self.utf7_encode,
        }
        
        encoder = encoders.get(encoding_type.lower())
        if encoder:
            return encoder(payload)
        return payload
    
    def get_all_variants(self, payload: str) -> List[str]:
        """الحصول على جميع أشكال الـ Payload"""
        variants = [payload]  # الأصلي
        
        # إضافة جميع الترميزات
        variants.extend(self.mixed_encoding(payload))
        
        # إضافة تقنيات WAF Bypass
        variants.extend(self.waf_bypass_techniques(payload))
        
        # إزالة المكررات
        return list(set(variants))