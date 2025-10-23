"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - SSRF Scanners  ⚔️               ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

Server-Side Request Forgery (SSRF) Scanners
-------------------------------------------
- SSRF Scanner (Basic & Advanced)
- Blind SSRF Scanner
- Cloud Metadata SSRF (AWS, Azure, GCP)
"""

from .ssrf_scanner import SSRFScanner
from .ssrf_blind import BlindSSRFScanner
from .ssrf_cloud import CloudMetadataSSRFScanner

__all__ = [
    'SSRFScanner',
    'BlindSSRFScanner',
    'CloudMetadataSSRFScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN | @ll bUg'

# Scanner metadata
SCANNERS = {
    'ssrf': {
        'name': 'SSRF Scanner',
        'class': SSRFScanner,
        'severity': 'CRITICAL',
        'cwe': 'CWE-918'
    },
    'blind_ssrf': {
        'name': 'Blind SSRF Scanner',
        'class': BlindSSRFScanner,
        'severity': 'HIGH',
        'cwe': 'CWE-918'
    },
    'cloud_ssrf': {
        'name': 'Cloud Metadata SSRF Scanner',
        'class': CloudMetadataSSRFScanner,
        'severity': 'CRITICAL',
        'cwe': 'CWE-918'
    }
}

def get_scanner(scanner_type: str, target: str, config: dict = None):
    """
    احصل على ماسح SSRF معين
    
    Args:
        scanner_type: نوع الماسح (ssrf, blind_ssrf, cloud_ssrf)
        target: الهدف المراد فحصه
        config: إعدادات الفحص
    
    Returns:
        Scanner instance
    """
    if scanner_type not in SCANNERS:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    
    scanner_class = SCANNERS[scanner_type]['class']
    return scanner_class(target, config)

def get_all_scanners(target: str, config: dict = None):
    """
    احصل على جميع ماسحات SSRF
    
    Args:
        target: الهدف المراد فحصه
        config: إعدادات الفحص
    
    Returns:
        List of scanner instances
    """
    return [
        scanner_info['class'](target, config)
        for scanner_info in SCANNERS.values()
    ]