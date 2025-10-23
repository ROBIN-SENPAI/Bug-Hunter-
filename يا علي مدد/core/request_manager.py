"""
request_manager.py
إدارة الطلبات المتقدمة مع إعادة المحاولة والتخزين المؤقت
"""

import requests
import time
from typing import Dict, Optional, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RequestManager:
    """إدارة متقدمة لطلبات HTTP"""
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = self._create_session()
        self.cache = {}
        self.request_count = 0
        
    def _create_session(self) -> requests.Session:
        """إنشاء Session مع إعادة محاولة تلقائية"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def send_request(self, 
                    url: str, 
                    method: str = "GET",
                    headers: Optional[Dict] = None,
                    data: Optional[Any] = None,
                    json: Optional[Dict] = None,
                    params: Optional[Dict] = None,
                    cookies: Optional[Dict] = None,
                    proxies: Optional[Dict] = None,
                    use_cache: bool = True,
                    allow_redirects: bool = True) -> Optional[requests.Response]:
        """
        إرسال طلب HTTP مع معالجة متقدمة
        """
        try:
            cache_key = f"{method}_{url}_{str(params)}_{str(data)}"
            
            # التحقق من Cache
            if use_cache and cache_key in self.cache:
                return self.cache[cache_key]
            
            start_time = time.time()
            
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json,
                params=params,
                cookies=cookies,
                proxies=proxies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=allow_redirects
            )
            
            elapsed_time = time.time() - start_time
            self.request_count += 1
            
            # حفظ في Cache
            if use_cache and response.status_code == 200:
                self.cache[cache_key] = response
            
            return response
            
        except requests.exceptions.Timeout:
            print(f"⏱️ Timeout: {url}")
            return None
            
        except requests.exceptions.ConnectionError:
            print(f"❌ Connection Error: {url}")
            return None
            
        except requests.exceptions.TooManyRedirects:
            print(f"🔄 Too Many Redirects: {url}")
            return None
            
        except Exception as e:
            print(f"❌ Request Error: {str(e)}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب GET"""
        return self.send_request(url, method="GET", **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب POST"""
        return self.send_request(url, method="POST", **kwargs)
    
    def put(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب PUT"""
        return self.send_request(url, method="PUT", **kwargs)
    
    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب DELETE"""
        return self.send_request(url, method="DELETE", **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب HEAD"""
        return self.send_request(url, method="HEAD", **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """طلب OPTIONS"""
        return self.send_request(url, method="OPTIONS", **kwargs)
    
    def clear_cache(self):
        """مسح الذاكرة المؤقتة"""
        self.cache.clear()
    
    def get_cache_size(self) -> int:
        """حجم الـ Cache"""
        return len(self.cache)
    
    def get_request_count(self) -> int:
        """عدد الطلبات المرسلة"""
        return self.request_count
    
    def close(self):
        """إغلاق الـ Session"""
        self.session.close()