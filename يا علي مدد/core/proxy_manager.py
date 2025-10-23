"""
proxy_manager.py
إدارة البروكسيات
"""

import random
from typing import List, Dict, Optional
import requests


class ProxyManager:
    """إدارة البروكسيات"""
    
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.working_proxies = []
        self.failed_proxies = []
    
    def add_proxy(self, proxy: str, proxy_type: str = 'http'):
        """
        إضافة بروكسي واحد
        
        Args:
            proxy: عنوان البروكسي (مثل: 127.0.0.1:8080)
            proxy_type: نوع البروكسي (http, https, socks5)
        """
        proxy_dict = {
            'http': f'{proxy_type}://{proxy}',
            'https': f'{proxy_type}://{proxy}'
        }
        self.proxies.append(proxy_dict)
    
    def add_proxies(self, proxies: List[str], proxy_type: str = 'http'):
        """إضافة قائمة بروكسيات"""
        for proxy in proxies:
            self.add_proxy(proxy, proxy_type)
    
    def load_from_file(self, filepath: str, proxy_type: str = 'http'):
        """تحميل بروكسيات من ملف"""
        try:
            with open(filepath, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
                self.add_proxies(proxies, proxy_type)
            print(f"✅ Loaded {len(proxies)} proxies from {filepath}")
        except Exception as e:
            print(f"❌ Error loading proxies: {str(e)}")
    
    def get_next_proxy(self) -> Optional[Dict]:
        """الحصول على البروكسي التالي (Round-robin)"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[Dict]:
        """الحصول على بروكسي عشوائي"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)
    
    def test_proxy(self, proxy: Dict, test_url: str = 'http://httpbin.org/ip', timeout: int = 10) -> bool:
        """اختبار بروكسي"""
        try:
            response = requests.get(test_url, proxies=proxy, timeout=timeout)
            if response.status_code == 200:
                self.working_proxies.append(proxy)
                return True
            return False
        except:
            self.failed_proxies.append(proxy)
            return False
    
    def test_all_proxies(self, test_url: str = 'http://httpbin.org/ip', timeout: int = 10):
        """اختبار جميع البروكسيات"""
        print(f"🔍 Testing {len(self.proxies)} proxies...")
        
        self.working_proxies.clear()
        self.failed_proxies.clear()
        
        for i, proxy in enumerate(self.proxies, 1):
            print(f"Testing {i}/{len(self.proxies)}...", end='\r')
            self.test_proxy(proxy, test_url, timeout)
        
        print(f"\n✅ Working proxies: {len(self.working_proxies)}")
        print(f"❌ Failed proxies: {len(self.failed_proxies)}")
        
        # استخدام البروكسيات العاملة فقط
        if self.working_proxies:
            self.proxies = self.working_proxies.copy()
    
    def remove_proxy(self, proxy: Dict):
        """حذف بروكسي"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
    
    def clear_proxies(self):
        """مسح جميع البروكسيات"""
        self.proxies.clear()
        self.working_proxies.clear()
        self.failed_proxies.clear()
        self.current_index = 0
    
    def get_proxy_count(self) -> int:
        """عدد البروكسيات"""
        return len(self.proxies)
    
    def has_proxies(self) -> bool:
        """هل يوجد بروكسيات؟"""
        return len(self.proxies) > 0
    
    def get_all_proxies(self) -> List[Dict]:
        """الحصول على جميع البروكسيات"""
        return self.proxies.copy()
    
    def rotate_proxy(self):
        """التبديل إلى البروكسي التالي"""
        return self.get_next_proxy()


class ProxyRotator:
    """محول البروكسيات التلقائي"""
    
    def __init__(self, proxy_manager: ProxyManager, rotation_mode: str = 'random'):
        """
        Args:
            proxy_manager: مدير البروكسيات
            rotation_mode: نمط التبديل (random, sequential)
        """
        self.proxy_manager = proxy_manager
        self.rotation_mode = rotation_mode
        self.request_count = 0
        self.rotation_interval = 10  # التبديل كل 10 طلبات
    
    def get_proxy_for_request(self) -> Optional[Dict]:
        """الحصول على بروكسي للطلب"""
        self.request_count += 1
        
        # التبديل التلقائي
        if self.request_count % self.rotation_interval == 0:
            if self.rotation_mode == 'random':
                return self.proxy_manager.get_random_proxy()
            else:
                return self.proxy_manager.get_next_proxy()
        
        # استخدام البروكسي الحالي
        if self.rotation_mode == 'random':
            return self.proxy_manager.get_random_proxy()
        else:
            return self.proxy_manager.get_next_proxy()
    
    def set_rotation_interval(self, interval: int):
        """تغيير فترة التبديل"""
        self.rotation_interval = interval