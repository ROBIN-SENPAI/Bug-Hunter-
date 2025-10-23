"""
XXE (XML External Entity) Scanners Package
===========================================

هذا المجلد يحتوي على ماسحات متخصصة لاكتشاف ثغرات XXE:

1. xxe_scanner.py - الماسح الأساسي لـ XXE
2. xxe_oob.py - ماسح XXE Out-of-Band
3. xxe_blind.py - ماسح Blind XXE

المؤلف: AlBaTTaR BUGS Team
الترخيص: MIT
"""

from .xxe_scanner import XXEScanner
from .xxe_oob import XXEOutOfBandScanner
from .xxe_blind import BlindXXEScanner

__all__ = [
    'XXEScanner',
    'XXEOutOfBandScanner', 
    'BlindXXEScanner'
]

__version__ = '1.0.0'
__author__ = 'AlBaTTaR BUGS Team'

# إعدادات افتراضية للماسحات
DEFAULT_CONFIG = {
    'timeout': 30,
    'max_payloads': 50,
    'test_file_read': True,
    'test_ssrf': True,
    'test_dos': False,  # خطير - يُستخدم فقط في بيئات الاختبار
    'oob_server': None,  # يجب تحديده للـ Out-of-Band
    'encoding_tests': ['utf-8', 'utf-16', 'iso-8859-1']
}

# أنواع XML Parsers الشائعة
VULNERABLE_PARSERS = {
    'php': ['simplexml_load_string', 'DOMDocument', 'XMLReader'],
    'java': ['DocumentBuilder', 'SAXParser', 'XMLReader'],
    'python': ['lxml.etree', 'xml.etree.ElementTree', 'xml.dom.minidom'],
    '.net': ['XmlDocument', 'XmlTextReader', 'XPathDocument'],
    'ruby': ['REXML', 'Nokogiri'],
}

def get_scanner(scanner_type='basic'):
    """
    الحصول على الماسح المناسب حسب النوع
    
    Args:
        scanner_type (str): نوع الماسح ('basic', 'oob', 'blind')
    
    Returns:
        Scanner instance
    """
    scanners = {
        'basic': XXEScanner,
        'oob': XXEOutOfBandScanner,
        'blind': BlindXXEScanner
    }
    
    scanner_class = scanners.get(scanner_type.lower())
    if not scanner_class:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    
    return scanner_class