"""
scan_orchestrator.py
منسق الفحص الرئيسي - يدير جميع الماسحات
"""

from typing import Dict, List, Optional
from datetime import datetime
import time


class ScanOrchestrator:
    """منسق الفحص الرئيسي"""
    
    def __init__(self, target: str, config: Dict):
        self.target = target
        self.config = config
        self.scan_id = self._generate_scan_id()
        self.start_time = None
        self.end_time = None
        self.results = {
            'vulnerabilities': [],
            'info': [],
            'statistics': {}
        }
        self.scanners = []
    
    def _generate_scan_id(self) -> str:
        """توليد معرف فريد للفحص"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"scan_{timestamp}"
    
    def register_scanner(self, scanner):
        """تسجيل ماسح جديد"""
        self.scanners.append(scanner)
    
    def start_scan(self, scan_type: str = 'full'):
        """بدء الفحص"""
        self.start_time = datetime.now()
        print(f"\n{'='*70}")
        print(f"🚀 Starting scan: {self.scan_id}")
        print(f"🎯 Target: {self.target}")
        print(f"📊 Scan Type: {scan_type}")
        print(f"⏰ Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        try:
            if scan_type == 'quick':
                self._quick_scan()
            elif scan_type == 'full':
                self._full_scan()
            elif scan_type == 'deep':
                self._deep_scan()
            else:
                self._full_scan()
            
            self.end_time = datetime.now()
            self._generate_statistics()
            
            return self.results
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user!")
            self.end_time = datetime.now()
            return self.results
        
        except Exception as e:
            print(f"\n❌ Scan error: {str(e)}")
            self.end_time = datetime.now()
            return self.results
    
    def _quick_scan(self):
        """فحص سريع - الثغرات الأساسية فقط"""
        print("⚡ Quick scan mode - Testing common vulnerabilities...\n")
        
        quick_scanners = ['sqli', 'xss', 'lfi']
        
        for scanner in self.scanners:
            if scanner.name.lower() in quick_scanners:
                self._run_scanner(scanner)
    
    def _full_scan(self):
        """فحص كامل - جميع الماسحات"""
        print("🔍 Full scan mode - Testing all vulnerabilities...\n")
        
        for scanner in self.scanners:
            self._run_scanner(scanner)
    
    def _deep_scan(self):
        """فحص عميق - مع fuzzing متقدم"""
        print("🎯 Deep scan mode - Advanced testing with fuzzing...\n")
        
        for scanner in self.scanners:
            self._run_scanner(scanner, deep_mode=True)
    
    def _run_scanner(self, scanner, deep_mode: bool = False):
        """تشغيل ماسح واحد"""
        try:
            print(f"📡 Running {scanner.name}...", end=' ')
            
            start = time.time()
            results = scanner.scan(self.target, deep_mode=deep_mode)
            elapsed = time.time() - start
            
            if results:
                self.results['vulnerabilities'].extend(results)
                print(f"✅ Found {len(results)} issues ({elapsed:.2f}s)")
            else:
                print(f"✅ Clean ({elapsed:.2f}s)")
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    def _generate_statistics(self):
        """توليد إحصائيات الفحص"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        # تصنيف حسب الخطورة
        critical = len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'critical'])
        high = len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'high'])
        medium = len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'medium'])
        low = len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'low'])
        info = len([v for v in self.results['vulnerabilities'] if v.get('severity') == 'info'])
        
        self.results['statistics'] = {
            'scan_id': self.scan_id,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': round(duration, 2),
            'duration_formatted': self._format_duration(duration),
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'by_severity': {
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'info': info
            },
            'scanners_used': len(self.scanners)
        }
    
    def _format_duration(self, seconds: float) -> str:
        """تنسيق مدة الفحص"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    def print_summary(self):
        """طباعة ملخص الفحص"""
        stats = self.results['statistics']
        
        print(f"\n{'='*70}")
        print("📊 SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"⏱️  Duration: {stats['duration_formatted']}")
        print(f"🎯 Total Issues: {stats['total_vulnerabilities']}")
        print(f"\n🔴 Critical: {stats['by_severity']['critical']}")
        print(f"🟠 High: {stats['by_severity']['high']}")
        print(f"🟡 Medium: {stats['by_severity']['medium']}")
        print(f"🟢 Low: {stats['by_severity']['low']}")
        print(f"ℹ️  Info: {stats['by_severity']['info']}")
        print(f"{'='*70}\n")
    
    def get_results(self) -> Dict:
        """الحصول على نتائج الفحص"""
        return self.results