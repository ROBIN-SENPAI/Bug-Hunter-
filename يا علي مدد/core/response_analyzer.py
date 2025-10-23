"""
response_analyzer.py
تحليل استجابات HTTP بذكاء
"""

import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup


class ResponseAnalyzer:
    """تحليل متقدم للاستجابات"""
    
    def __init__(self):
        # أنماط أخطاء SQL
        self.sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"Npgsql\.",
            r"Driver.* SQL[-_ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlClient\.",
            r"Microsoft SQL Native Client",
            r"ODBC SQL Server Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
            r"syntax error.*SQL",
            r"mysql_fetch",
            r"mysql_num_rows"
        ]
        
        # أنماط XSS
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"javascript:",
            r"<img[^>]*src",
            r"<svg[^>]*onload"
        ]
        
        # أنماط Command Injection
        self.command_patterns = [
            r"root:x:0:0:",
            r"daemon:.*:bin",
            r"\[boot loader\]",
            r"Linux version",
            r"Windows.*\[Version",
            r"Microsoft Windows"
        ]
        
        # أنماط معلومات حساسة
        self.sensitive_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)[\'":\s=]+[a-zA-Z0-9_\-]{20,}',
            'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
            'password': r'(?i)(password|passwd|pwd)[\'":\s=]+[^\s\'\"]{6,}',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ssh_key': r'ssh-rsa [A-Za-z0-9+/=]+',
            'database_url': r'(?i)(mysql|postgresql|mongodb)://[^\s]+'
        }
    
    def analyze(self, response) -> Dict:
        """تحليل شامل للاستجابة"""
        if not response:
            return {'error': 'No response'}
        
        analysis = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'encoding': response.encoding,
            'sql_errors': self.detect_sql_errors(response.text),
            'xss_reflected': self.detect_xss(response.text),
            'command_injection': self.detect_command_injection(response.text),
            'sensitive_data': self.find_sensitive_data(response.text),
            'security_headers': self.check_security_headers(response.headers),
            'cookies': self.analyze_cookies(response.cookies),
            'redirects': len(response.history),
            'forms': self.extract_forms(response.text),
            'links': self.extract_links(response.text),
            'comments': self.extract_comments(response.text)
        }
        
        return analysis
    
    def detect_sql_errors(self, text: str) -> List[str]:
        """كشف أخطاء SQL"""
        found_errors = []
        for pattern in self.sql_errors:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found_errors.extend(matches)
        return found_errors
    
    def detect_xss(self, text: str) -> bool:
        """كشف XSS محتمل"""
        for pattern in self.xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def detect_command_injection(self, text: str) -> List[str]:
        """كشف Command Injection"""
        found = []
        for pattern in self.command_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.extend(matches)
        return found
    
    def find_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        """البحث عن بيانات حساسة"""
        findings = {}
        for data_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[data_type] = matches[:5]  # أول 5 نتائج فقط
        return findings
    
    def check_security_headers(self, headers: Dict) -> Dict:
        """فحص Security Headers"""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy')
        }
        
        missing = [k for k, v in security_headers.items() if not v]
        
        return {
            'present': {k: v for k, v in security_headers.items() if v},
            'missing': missing,
            'score': len(security_headers) - len(missing)
        }
    
    def analyze_cookies(self, cookies) -> List[Dict]:
        """تحليل الكوكيز"""
        cookie_analysis = []
        
        for cookie in cookies:
            cookie_analysis.append({
                'name': cookie.name,
                'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'samesite': cookie.get_nonstandard_attr('SameSite'),
                'domain': cookie.domain,
                'path': cookie.path
            })
        
        return cookie_analysis
    
    def extract_forms(self, html: str) -> List[Dict]:
        """استخراج النماذج من HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action'),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value')
                    })
                
                forms.append(form_data)
            
            return forms
        except:
            return []
    
    def extract_links(self, html: str) -> List[str]:
        """استخراج الروابط"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = []
            
            for link in soup.find_all('a', href=True):
                links.append(link['href'])
            
            return list(set(links))[:50]  # أول 50 رابط فريد
        except:
            return []
    
    def extract_comments(self, html: str) -> List[str]:
        """استخراج التعليقات من HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            return [comment.strip() for comment in comments[:10]]  # أول 10 تعليقات
        except:
            return []
    
    def compare_responses(self, response1, response2) -> Dict:
        """مقارنة استجابتين"""
        return {
            'status_code_diff': response1.status_code != response2.status_code,
            'content_length_diff': abs(len(response1.content) - len(response2.content)),
            'time_diff': abs(response1.elapsed.total_seconds() - response2.elapsed.total_seconds()),
            'headers_diff': set(response1.headers.keys()) - set(response2.headers.keys()),
            'same_content': response1.text == response2.text
        }