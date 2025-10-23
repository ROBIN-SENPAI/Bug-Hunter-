"""
AlBaTTaR BUGS - File Inclusion Scanners Package
================================================
Advanced scanners for file inclusion vulnerabilities

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

from .lfi_scanner import LFIScanner
from .rfi_scanner import RFIScanner
from .path_traversal import PathTraversalScanner
from .file_disclosure import FileDisclosureScanner

__all__ = [
    'LFIScanner',
    'RFIScanner', 
    'PathTraversalScanner',
    'FileDisclosureScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN | @ll bUg'