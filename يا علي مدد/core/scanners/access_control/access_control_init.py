"""
Access Control Scanners Module
كشف ثغرات التحكم بالوصول
"""

from .idor_scanner import IDORScanner
from .privilege_escalation import PrivilegeEscalationScanner
from .path_confusion import PathConfusionScanner
from .cors_scanner import CORSScanner

__all__ = [
    'IDORScanner',
    'PrivilegeEscalationScanner',
    'PathConfusionScanner',
    'CORSScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN | @ll bUg'
