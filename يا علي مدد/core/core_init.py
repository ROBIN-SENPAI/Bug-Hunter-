"""
AlBaTTaR BUGS - Core Module
The main engine powering the vulnerability scanner
"""

from .target_validator import TargetValidator
from .target_analyzer import TargetAnalyzer
from .http_handler import HTTPHandler
from .request_manager import RequestManager
from .response_analyzer import ResponseAnalyzer
from .session_manager import SessionManager
from .payload_manager import PayloadManager
from .payload_encoder import PayloadEncoder
from .scan_orchestrator import ScanOrchestrator
from .thread_manager import ThreadManager
from .rate_limiter import RateLimiter
from .proxy_manager import ProxyManager
from .authentication import Authentication
from .fingerprinting import Fingerprinting
from .vulnerability_scorer import VulnerabilityScorer

__all__ = [
    'TargetValidator',
    'TargetAnalyzer',
    'HTTPHandler',
    'RequestManager',
    'ResponseAnalyzer',
    'SessionManager',
    'PayloadManager',
    'PayloadEncoder',
    'ScanOrchestrator',
    'ThreadManager',
    'RateLimiter',
    'ProxyManager',
    'Authentication',
    'Fingerprinting',
    'VulnerabilityScorer',
]

__version__ = '1.0.0'
