"""
Session Fixation/Hijacking Scanner
كشف ثغرات تثبيت واختطاف الجلسات
"""

import requests
from typing import List, Dict, Optional
import hashlib
import time


class SessionFixationScanner:
    """ماسح ثغرات Session"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting Session Fixation scan on: {self.target}")
        
        # 1. Session Fixation
        self._test_session_fixation()
        
        # 2. Session ID in URL
        self._test_session_in_url()
        
        # 3. Predictable Session IDs
        self._test_predictable_sessions()
        
        # 4. Session Not Regenerated After Login
        self._test_session_regeneration()
        
        # 5. Weak Session Cookie Attributes
        self._test_cookie_attributes()
        
        # 6. Session Hijacking via XSS
        self._test_session_hijacking()
        
        print(f"✅ Found {len(self.vulnerabilities)} session vulnerabilities")
        return self.vulnerabilities
    
    def _test_session_fixation(self):
        """اختبار Session Fixation"""
        print("  📡 Testing session fixation...")
        
        try:
            session1 = requests.Session()
            
            # الخطوة 1: الحصول على session قبل تسجيل الدخول
            response1 = session1.get(self.target, timeout=10)
            cookies_before = dict(session1.cookies)
            
            if not cookies_before:
                return
            
            # الخطوة 2: محاولة تسجيل دخول مع نفس الـ session
            login_data = {
                'username': 'test',
                'password': 'test123'
            }
            
            response2 = session1.post(self.target, data=login_data, timeout=10)
            cookies_after = dict(session1.cookies)
            
            # الخطوة 3: التحقق إذا لم يتغير Session ID
            session_id_before = self._extract_session_id(cookies_before)
            session_id_after = self._extract_session_id(cookies_after)
            
            if session_id_before and session_id_after and session_id_before == session_id_after:
                self.vulnerabilities.append({
                    'type': 'Session Security',
                    'subtype': 'Session Fixation',
                    'severity': 'high',
                    'url': self.target,
                    'session_id_before': session_id_before[:20] + '...',
                    'session_id_after': session_id_after[:20] + '...',
                    'confidence': 85,
                    'description': 'Session ID does not change after authentication',
                    'remediation': 'Regenerate session ID after successful login'
                })
                print("    ✅ Session fixation vulnerability found!")
                
        except Exception as e:
            pass
    
    def _test_session_in_url(self):
        """اختبار Session ID في URL"""
        print("  📡 Testing session ID in URL...")
        
        try:
            session = requests.Session()
            response = session.get(self.target, timeout=10, allow_redirects=True)
            
            # البحث عن session في URL
            session_patterns = [
                'sessionid=', 'session_id=', 'session=',
                'sid=', 'phpsessid=', 'jsessionid=',
                'aspsessionid=', 'cfid=', 'cftoken='
            ]
            
            url_lower = response.url.lower()
            
            for pattern in session_patterns:
                if pattern in url_lower:
                    self.vulnerabilities.append({
                        'type': 'Session Security',
                        'subtype': 'Session ID in URL',
                        'severity': 'medium',
                        'url': response.url,
                        'pattern_found': pattern,
                        'confidence': 90,
                        'description': 'Session ID exposed in URL (vulnerable to referrer leakage)',
                        'remediation': 'Use cookies instead of URL parameters for session IDs'
                    })
                    print(f"    ✅ Session ID in URL: {pattern}")
                    break
                    
        except Exception as e:
            pass
    
    def _test_predictable_sessions(self):
        """اختبار Session IDs القابلة للتنبؤ"""
        print("  📡 Testing predictable session IDs...")
        
        try:
            session_ids = []
            
            # جمع عدة session IDs
            for i in range(5):
                session = requests.Session()
                response = session.get(self.target, timeout=10)
                
                session_id = self._extract_session_id(dict(session.cookies))
                if session_id:
                    session_ids.append(session_id)
                
                time.sleep(0.5)
            
            if len(session_ids) >= 3:
                # فحص إذا كانت متسلسلة أو متشابهة
                if self._are_sessions_predictable(session_ids):
                    self.vulnerabilities.append({
                        'type': 'Session Security',
                        'subtype': 'Predictable Session IDs',
                        'severity': 'critical',
                        'url': self.target,
                        'sample_sessions': [s[:20] + '...' for s in session_ids[:3]],
                        'confidence': 75,
                        'description': 'Session IDs appear to be predictable',
                        'remediation': 'Use cryptographically secure random session IDs'
                    })
                    print("    ✅ Predictable session IDs found!")
                    
        except Exception as e:
            pass
    
    def _test_session_regeneration(self):
        """اختبار عدم تجديد الجلسة بعد تسجيل الدخول"""
        print("  📡 Testing session regeneration after login...")
        
        try:
            session = requests.Session()
            
            # قبل تسجيل الدخول
            response1 = session.get(self.target, timeout=10)
            session_before = dict(session.cookies)
            
            # محاولة تسجيل دخول
            login_data = {'username': 'admin', 'password': 'admin123'}
            response2 = session.post(self.target, data=login_data, timeout=10)
            session_after = dict(session.cookies)
            
            # مقارنة
            if session_before == session_after and session_before:
                self.vulnerabilities.append({
                    'type': 'Session Security',
                    'subtype': 'No Session Regeneration',
                    'severity': 'medium',
                    'url': self.target,
                    'confidence': 70,
                    'description': 'Session is not regenerated after login',
                    'remediation': 'Regenerate session after privilege level change'
                })
                print("    ⚠️  Session not regenerated after login")
                
        except Exception as e:
            pass
    
    def _test_cookie_attributes(self):
        """اختبار خصائص Session Cookie"""
        print("  📡 Testing session cookie attributes...")
        
        try:
            session = requests.Session()
            response = session.get(self.target, timeout=10)
            
            issues = []
            
            for cookie in session.cookies:
                # فحص HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append({
                        'attribute': 'HttpOnly',
                        'cookie_name': cookie.name,
                        'description': 'Cookie accessible via JavaScript (XSS risk)'
                    })
                
                # فحص Secure
                if not cookie.secure and 'https' in self.target:
                    issues.append({
                        'attribute': 'Secure',
                        'cookie_name': cookie.name,
                        'description': 'Cookie can be transmitted over HTTP'
                    })
                
                # فحص SameSite
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append({
                        'attribute': 'SameSite',
                        'cookie_name': cookie.name,
                        'description': 'Cookie vulnerable to CSRF attacks'
                    })
            
            if issues:
                self.vulnerabilities.append({
                    'type': 'Session Security',
                    'subtype': 'Weak Cookie Attributes',
                    'severity': 'medium',
                    'url': self.target,
                    'missing_attributes': issues,
                    'confidence': 95,
                    'description': 'Session cookies missing security attributes',
                    'remediation': 'Set HttpOnly, Secure, and SameSite attributes'
                })
                print(f"    ⚠️  Found {len(issues)} cookie security issues")
                
        except Exception as e:
            pass
    
    def _test_session_hijacking(self):
        """اختبار إمكانية اختطاف الجلسة"""
        print("  📡 Testing session hijacking possibility...")
        
        try:
            session1 = requests.Session()
            response1 = session1.get(self.target, timeout=10)
            cookies1 = dict(session1.cookies)
            
            if not cookies1:
                return
            
            # استخراج Session ID
            session_id = self._extract_session_id(cookies1)
            
            if not session_id:
                return
            
            # إنشاء جلسة جديدة واستخدام نفس Session ID
            session2 = requests.Session()
            
            # نسخ الكوكيز
            for name, value in cookies1.items():
                session2.cookies.set(name, value)
            
            # محاولة الوصول
            response2 = session2.get(self.target, timeout=10)
            
            # إذا نجح الوصول بنفس الجلسة
            if response2.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Session Security',
                    'subtype': 'Session Hijacking Possible',
                    'severity': 'high',
                    'url': self.target,
                    'session_id': session_id[:20] + '...',
                    'confidence': 80,
                    'description': 'Session can be hijacked if session ID is stolen',
                    'remediation': 'Implement additional security measures (IP binding, User-Agent check)'
                })
                print("    ⚠️  Session hijacking is possible")
                
        except Exception as e:
            pass
    
    def _extract_session_id(self, cookies: dict) -> Optional[str]:
        """استخراج Session ID من Cookies"""
        session_keys = [
            'sessionid', 'session_id', 'session',
            'sid', 'phpsessid', 'jsessionid',
            'aspsessionid', 'cfid', 'auth_token',
            'token', 'csrf_token'
        ]
        
        for key in cookies:
            if key.lower() in session_keys:
                return cookies[key]
        
        # إذا لم نجد، نأخذ أول cookie
        if cookies:
            return list(cookies.values())[0]
        
        return None
    
    def _are_sessions_predictable(self, session_ids: List[str]) -> bool:
        """فحص إذا كانت Session IDs قابلة للتنبؤ"""
        if len(session_ids) < 3:
            return False
        
        # فحص إذا كانت متسلسلة (أرقام)
        try:
            numbers = [int(sid) for sid in session_ids]
            diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
            
            # إذا كانت الفروقات متساوية أو قريبة
            if len(set(diffs)) <= 2:
                return True
        except:
            pass
        
        # فحص التشابه في الأحرف
        similarity_count = 0
        for i in range(len(session_ids)-1):
            common = sum(1 for a, b in zip(session_ids[i], session_ids[i+1]) if a == b)
            similarity = common / max(len(session_ids[i]), len(session_ids[i+1]))
            
            if similarity > 0.7:  # 70% متشابهة
                similarity_count += 1
        
        if similarity_count >= 2:
            return True
        
        # فحص إذا كانت timestamp-based
        import re
        timestamps = []
        for sid in session_ids:
            matches = re.findall(r'\d{10,}', sid)
            if matches:
                timestamps.append(int(matches[0]))
        
        if len(timestamps) >= 3:
            diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if all(d < 10 for d in diffs):  # فرق أقل من 10 ثواني
                return True
        
        return False
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'Session Fixation/Hijacking Scanner',
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


if __name__ == "__main__":
    target = "http://testphp.vulnweb.com/login.php"
    scanner = SessionFixationScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 SESSION SECURITY SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
    print(f"Medium: {report['summary']['medium']}")