"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - Crypto Scanners Package  ⚔️     ║
║              Cryptographic Vulnerabilities Scanner          ║
╚══════════════════════════════════════════════════════════════╝

Package: scanners.crypto
Description: Advanced cryptographic vulnerability detection
Author: ROBIN | @ll bUg
Version: 1.0.0
"""

from .weak_crypto import WeakCryptoScanner
from .padding_oracle import PaddingOracleScanner
from .hash_collision import HashCollisionScanner

__all__ = [
    'WeakCryptoScanner',
    'PaddingOracleScanner',
    'HashCollisionScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN'

# Scanner metadata
SCANNERS = {
    'weak_crypto': {
        'class': WeakCryptoScanner,
        'name': 'Weak Cryptography Scanner',
        'description': 'Detects weak encryption algorithms and configurations',
        'severity': 'high',
        'cwe': ['CWE-327', 'CWE-326']
    },
    'padding_oracle': {
        'class': PaddingOracleScanner,
        'name': 'Padding Oracle Attack Scanner',
        'description': 'Detects padding oracle vulnerabilities in CBC mode',
        'severity': 'high',
        'cwe': ['CWE-326']
    },
    'hash_collision': {
        'class': HashCollisionScanner,
        'name': 'Hash Collision Scanner',
        'description': 'Detects weak hashing algorithms and length extension attacks',
        'severity': 'medium',
        'cwe': ['CWE-328', 'CWE-916']
    }
}

def get_scanner(scanner_name):
    """
    Get scanner instance by name
    
    Args:
        scanner_name: Name of the scanner
        
    Returns:
        Scanner class or None
    """
    scanner_info = SCANNERS.get(scanner_name)
    return scanner_info['class'] if scanner_info else None

def list_scanners():
    """
    List all available crypto scanners
    
    Returns:
        Dictionary of scanner information
    """
    return SCANNERS
