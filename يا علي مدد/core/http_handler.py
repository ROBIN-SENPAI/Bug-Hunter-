"""
HTTP Handler - Handles all HTTP/HTTPS requests
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class HTTPHandler:
    """Handle HTTP/HTTPS requests with advanced features"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.follow_redirects = self.config.get('follow_redirects', True)
        self.max_redirects = self.config.get('max_redirects', 5)
        self.max_retries = self.config.get('max_retries', 3)
        
        self.session = self._create_session()
    
    def _create_session(self):
        """Create requests session with retry logic"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def get(self, url, **kwargs):
        """Send GET request"""
        return self._request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        """Send POST request"""
        return self._request('POST', url, **kwargs)
    
    def put(self, url, **kwargs):
        """Send PUT request"""
        return self._request('PUT', url, **kwargs)
    
    def delete(self, url, **kwargs):
        """Send DELETE request"""
        return self._request('DELETE', url, **kwargs)
    
    def head(self, url, **kwargs):
        """Send HEAD request"""
        return self._request('HEAD', url, **kwargs)
    
    def options(self, url, **kwargs):
        """Send OPTIONS request"""
        return self._request('OPTIONS', url, **kwargs)
    
    def patch(self, url, **kwargs):
        """Send PATCH request"""
        return self._request('PATCH', url, **kwargs)
    
    def _request(self, method, url, **kwargs):
        """Send HTTP request with error handling"""
        # Set defaults
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('allow_redirects', self.follow_redirects)
        
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request timeout for {url}")
        except requests.exceptions.ConnectionError:
            raise ConnectionError(f"Connection error for {url}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")
    
    def set_headers(self, headers):
        """Set default headers for all requests"""
        self.session.headers.update(headers)
    
    def set_cookies(self, cookies):
        """Set cookies"""
        self.session.cookies.update(cookies)
    
    def set_proxy(self, proxy):
        """Set proxy"""
        proxies = {
            'http': proxy,
            'https': proxy
        }
        self.session.proxies.update(proxies)
    
    def set_auth(self, username, password, auth_type='basic'):
        """Set authentication"""
        if auth_type == 'basic':
            from requests.auth import HTTPBasicAuth
            self.session.auth = HTTPBasicAuth(username, password)
        elif auth_type == 'digest':
            from requests.auth import HTTPDigestAuth
            self.session.auth = HTTPDigestAuth(username, password)
    
    def close(self):
        """Close session"""
        self.session.close()
