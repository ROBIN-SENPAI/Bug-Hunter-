"""
rate_limiter.py
التحكم في معدل الطلبات (Rate Limiting)
"""

import time
import threading
from collections import deque
from typing import Optional


class RateLimiter:
    """محدد معدل الطلبات"""
    
    def __init__(self, max_requests: int = 10, time_window: float = 1.0):
        """
        Args:
            max_requests: الحد الأقصى للطلبات
            time_window: النافذة الزمنية بالثواني
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """الانتظار إذا تم تجاوز الحد"""
        with self.lock:
            now = time.time()
            
            # إزالة الطلبات القديمة
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            # التحقق من الحد
            if len(self.requests) >= self.max_requests:
                sleep_time = self.time_window - (now - self.requests[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    # إزالة الطلبات القديمة مرة أخرى
                    now = time.time()
                    while self.requests and self.requests[0] < now - self.time_window:
                        self.requests.popleft()
            
            # إضافة الطلب الحالي
            self.requests.append(time.time())
    
    def can_proceed(self) -> bool:
        """التحقق من إمكانية المتابعة"""
        with self.lock:
            now = time.time()
            
            # إزالة الطلبات القديمة
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            return len(self.requests) < self.max_requests
    
    def reset(self):
        """إعادة تعيين المحدد"""
        with self.lock:
            self.requests.clear()
    
    def get_current_rate(self) -> int:
        """الحصول على المعدل الحالي"""
        with self.lock:
            now = time.time()
            
            # إزالة الطلبات القديمة
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            return len(self.requests)
    
    def set_limits(self, max_requests: int, time_window: float):
        """تغيير الحدود"""
        with self.lock:
            self.max_requests = max_requests
            self.time_window = time_window


class AdaptiveRateLimiter:
    """محدد معدل تكيفي (يتكيف مع استجابة السيرفر)"""
    
    def __init__(self, initial_rate: int = 10, min_rate: int = 1, max_rate: int = 50):
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.limiter = RateLimiter(initial_rate, 1.0)
        self.success_count = 0
        self.fail_count = 0
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """الانتظار مع التكيف"""
        self.limiter.wait_if_needed()
    
    def report_success(self):
        """تسجيل نجاح الطلب"""
        with self.lock:
            self.success_count += 1
            self.fail_count = 0
            
            # زيادة المعدل تدريجياً
            if self.success_count >= 10:
                self.increase_rate()
                self.success_count = 0
    
    def report_failure(self, status_code: int = 0):
        """تسجيل فشل الطلب"""
        with self.lock:
            self.fail_count += 1
            self.success_count = 0
            
            # تقليل المعدل
            if status_code == 429 or self.fail_count >= 3:
                self.decrease_rate()
                self.fail_count = 0
    
    def increase_rate(self):
        """زيادة المعدل"""
        if self.current_rate < self.max_rate:
            self.current_rate = min(self.current_rate + 5, self.max_rate)
            self.limiter.set_limits(self.current_rate, 1.0)
            print(f"📈 Rate increased to {self.current_rate} req/s")
    
    def decrease_rate(self):
        """تقليل المعدل"""
        if self.current_rate > self.min_rate:
            self.current_rate = max(self.current_rate - 5, self.min_rate)
            self.limiter.set_limits(self.current_rate, 1.0)
            print(f"📉 Rate decreased to {self.current_rate} req/s")
    
    def get_current_rate(self) -> int:
        """الحصول على المعدل الحالي"""
        return self.current_rate


class DelayController:
    """التحكم في التأخير بين الطلبات"""
    
    def __init__(self, min_delay: float = 0.1, max_delay: float = 2.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.current_delay = min_delay
        self.last_request_time = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """الانتظار للتأخير المطلوب"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request_time
            
            if elapsed < self.current_delay:
                time.sleep(self.current_delay - elapsed)
            
            self.last_request_time = time.time()
    
    def increase_delay(self, factor: float = 1.5):
        """زيادة التأخير"""
        self.current_delay = min(self.current_delay * factor, self.max_delay)
    
    def decrease_delay(self, factor: float = 0.8):
        """تقليل التأخير"""
        self.current_delay = max(self.current_delay * factor, self.min_delay)
    
    def reset_delay(self):
        """إعادة تعيين التأخير"""
        self.current_delay = self.min_delay