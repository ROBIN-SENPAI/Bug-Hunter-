"""
thread_manager.py
إدارة الخيوط المتعددة (Multi-threading)
"""

import threading
import queue
from typing import Callable, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class ThreadManager:
    """إدارة متقدمة للخيوط المتعددة"""
    
    def __init__(self, max_threads: int = 10):
        self.max_threads = max_threads
        self.task_queue = queue.Queue()
        self.results = []
        self.errors = []
        self.lock = threading.Lock()
        self.completed_tasks = 0
        self.total_tasks = 0
        self.active = False
    
    def add_task(self, func: Callable, *args, **kwargs):
        """إضافة مهمة إلى قائمة الانتظار"""
        self.task_queue.put((func, args, kwargs))
        self.total_tasks += 1
    
    def add_tasks(self, tasks: List[tuple]):
        """إضافة مهام متعددة"""
        for task in tasks:
            func = task[0]
            args = task[1] if len(task) > 1 else ()
            kwargs = task[2] if len(task) > 2 else {}
            self.add_task(func, *args, **kwargs)
    
    def worker(self):
        """العامل الذي ينفذ المهام"""
        while self.active:
            try:
                # الحصول على مهمة من القائمة
                func, args, kwargs = self.task_queue.get(timeout=1)
                
                try:
                    # تنفيذ المهمة
                    result = func(*args, **kwargs)
                    
                    with self.lock:
                        self.results.append(result)
                        self.completed_tasks += 1
                
                except Exception as e:
                    with self.lock:
                        self.errors.append({
                            'function': func.__name__,
                            'error': str(e),
                            'args': args,
                            'kwargs': kwargs
                        })
                        self.completed_tasks += 1
                
                finally:
                    self.task_queue.task_done()
            
            except queue.Empty:
                continue
    
    def start(self):
        """بدء تشغيل الخيوط"""
        self.active = True
        self.threads = []
        
        for _ in range(self.max_threads):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            self.threads.append(thread)
    
    def wait_completion(self, show_progress: bool = True):
        """انتظار اكتمال جميع المهام"""
        if show_progress:
            self._show_progress()
        
        self.task_queue.join()
        self.active = False
        
        for thread in self.threads:
            thread.join()
    
    def _show_progress(self):
        """عرض تقدم التنفيذ"""
        while self.completed_tasks < self.total_tasks:
            progress = (self.completed_tasks / self.total_tasks) * 100
            bar_length = 40
            filled = int(bar_length * self.completed_tasks / self.total_tasks)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            print(f'\r[{bar}] {progress:.1f}% ({self.completed_tasks}/{self.total_tasks})', 
                  end='', flush=True)
            time.sleep(0.1)
        
        print()  # سطر جديد بعد الانتهاء
    
    def get_results(self) -> List[Any]:
        """الحصول على النتائج"""
        return self.results
    
    def get_errors(self) -> List[Dict]:
        """الحصول على الأخطاء"""
        return self.errors
    
    def clear(self):
        """مسح النتائج والأخطاء"""
        self.results.clear()
        self.errors.clear()
        self.completed_tasks = 0
        self.total_tasks = 0
    
    def execute_parallel(self, func: Callable, items: List[Any], **kwargs) -> List[Any]:
        """تنفيذ دالة على قائمة عناصر بشكل متوازي"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(func, item, **kwargs) for item in items]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.errors.append(str(e))
        
        return results
    
    def execute_with_timeout(self, func: Callable, timeout: int, *args, **kwargs) -> Optional[Any]:
        """تنفيذ دالة مع timeout"""
        result = [None]
        exception = [None]
        
        def wrapper():
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            return None  # Timeout
        
        if exception[0]:
            raise exception[0]
        
        return result[0]


class TaskPool:
    """مجموعة مهام متقدمة"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
    
    def submit(self, func: Callable, *args, **kwargs):
        """إرسال مهمة"""
        return self.executor.submit(func, *args, **kwargs)
    
    def map(self, func: Callable, items: List[Any]) -> List[Any]:
        """تطبيق دالة على قائمة"""
        return list(self.executor.map(func, items))
    
    def shutdown(self, wait: bool = True):
        """إغلاق المجموعة"""
        self.executor.shutdown(wait=wait)