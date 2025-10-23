"""
XSS Scanner Module
==================
مجموعة شاملة من ماسحات ثغرات XSS

Scanners:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Blind XSS
- Mutation XSS (mXSS)
"""

from .reflected_xss import ReflectedXSSScanner
from .stored_xss import StoredXSSScanner
from .dom_xss import DOMXSSScanner
from .blind_xss import BlindXSSScanner
from .mutation_xss import MutationXSSScanner

__all__ = [
    'ReflectedXSSScanner',
    'StoredXSSScanner',
    'DOMXSSScanner',
    'BlindXSSScanner',
    'MutationXSSScanner'
]

__version__ = '1.0.0'
__author__ = 'AlBaTTaR BUGS Team'
