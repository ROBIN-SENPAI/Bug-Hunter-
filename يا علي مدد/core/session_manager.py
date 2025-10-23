"""
session_manager.py
إدارة الجلسات والكوكيز
"""

import requests
from typing import Dict, Optional
from requests.auth import HTTPBasicAuth, HTTPDigestAuth


class SessionManager:
    """إدارة الجلسات وال Cookies"""
    
    def __init__(self):
        self.sessions = {}
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def create_session(self, session_id: str = "default") -> requests.Session:
        """إنشاء جلسة جديدة"""
        try:
            session = requests.Session()
            session.headers.update(self.default_headers)
            self.sessions[session_id] = session
            return session
            
        except Exception as e:
            print(f"❌ Error creating session: {str(e)}")
            return None
    
    def get_session(self, session_id: str = "default") -> Optional[requests.Session]:
        """الحصول على جلسة موجودة"""
        if session_id not in self.sessions:
            return self.create_session(session_id)
        return self.sessions[session_id]
    
    def set_cookies(self, session_id: str, cookies: Dict):
        """تعيين Cookies للجلسة"""
        session = self.get_session(session_id)
        if session:
            session.cookies.update(cookies)
    
    def get_cookies(self, session_id: str = "default") -> Dict:
        """الحصول على Cookies من الجلسة"""
        session = self.get_session(session_id)
        if session:
            return requests.utils.dict_from_cookiejar(session.cookies)
        return {}
    
    def set_headers(self, session_id: str, headers: Dict):
        """تعيين Headers للجلسة"""
        session = self.get_session(session_id)
        if session:
            session.headers.update(headers)
    
    def get_headers(self, session_id: str = "default") -> Dict:
        """الحصول على Headers"""
        session = self.get_session(session_id)
        if session:
            return dict(session.headers)
        return {}
    
    def authenticate(self, session_id: str, auth_type: str, credentials: Dict) -> bool:
        """مصادقة الجلسة"""
        try:
            session = self.get_session(session_id)
            
            if auth_type == "basic":
                session.auth = HTTPBasicAuth(credentials['username'], credentials['password'])
                
            elif auth_type == "digest":
                session.auth = HTTPDigestAuth(credentials['username'], credentials['password'])
                
            elif auth_type == "bearer":
                session.headers['Authorization'] = f"Bearer {credentials['token']}"
                
            elif auth_type == "api_key":
                session.headers[credentials.get('header_name', 'X-API-Key')] = credentials['api_key']
            
            elif auth_type == "custom":
                session.headers['Authorization'] = credentials['value']
            
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {str(e)}")
            return False
    
    def set_proxy(self, session_id: str, proxy: Dict):
        """تعيين Proxy للجلسة"""
        session = self.get_session(session_id)
        if session:
            session.proxies.update(proxy)
    
    def close_session(self, session_id: str):
        """إغلاق جلسة"""
        if session_id in self.sessions:
            self.sessions[session_id].close()
            del self.sessions[session_id]
    
    def close_all_sessions(self):
        """إغلاق جميع الجلسات"""
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
    
    def session_exists(self, session_id: str) -> bool:
        """التحقق من وجود جلسة"""
        return session_id in self.sessions
    
    def get_session_count(self) -> int:
        """عدد الجلسات النشطة"""
        return len(self.sessions)