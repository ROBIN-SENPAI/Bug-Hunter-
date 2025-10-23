"""
Authentication Scanners Module
كشف ثغرات المصادقة والجلسات
"""

from .auth_bypass import AuthBypassScanner
from .weak_credentials import WeakCredentialsScanner
from .jwt_vulnerabilities import JWTScanner
from .session_fixation import SessionFixationScanner
from .oauth_scanner import OAuthScanner

__all__ = [
    'AuthBypassScanner',
    'WeakCredentialsScanner',
    'JWTScanner',
    'SessionFixationScanner',
    'OAuthScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN | @ll bUg'
