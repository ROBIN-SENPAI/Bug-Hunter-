"""
Target Analyzer - Analyzes target information and characteristics
"""

import requests
import socket
import ssl
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re


class TargetAnalyzer:
    """Analyze target characteristics and gather information"""
    
    def __init__(self, target, config=None):
        self.target = target
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self.info = {}
        
    def analyze(self):
        """Perform complete target analysis"""
        self.info['url'] = self.target
        self.info['domain'] = self._get_domain()
        self.info['ip'] = self._get_ip_address()
        self.info['server'] = self._detect_server()
        self.info['technologies'] = self._detect_technologies()
        self.info['headers'] = self._get_security_headers()
        self.info['ssl'] = self._analyze_ssl()
        self.info['cms'] = self._detect_cms()
        self.info['waf'] = self._detect_waf()
        
        return self.info
    
    def _get_domain(self):
        """Extract domain from target"""
        parsed = urlparse(self.target)
        return parsed.netloc.split(':')[0]
    
    def _get_ip_address(self):
        """Get IP address of target"""
        try:
            domain = self._get_domain()
            ip = socket.gethostbyname(domain)
            return ip
        except Exception:
            return None
    
    def _detect_server(self):
        """Detect web server"""
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            server_info = {
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                'status_code': response.status_code
            }
            
            return server_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_technologies(self):
        """Detect technologies used"""
        technologies = {
            'languages': [],
            'frameworks': [],
            'libraries': [],
            'cms': None
        }
        
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False
            )
            
            headers = response.headers
            content = response.text
            
            # Language detection
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By'].lower()
                if 'php' in powered_by:
                    technologies['languages'].append('PHP')
                elif 'asp.net' in powered_by:
                    technologies['languages'].append('ASP.NET')
            
            # Framework detection from headers
            if 'X-AspNet-Version' in headers:
                technologies['frameworks'].append('ASP.NET')
            
            if 'X-Drupal-Cache' in headers:
                technologies['frameworks'].append('Drupal')
            
            # Detection from HTML
            soup = BeautifulSoup(content, 'html.parser')
            
            # WordPress
            if 'wp-content' in content or 'wp-includes' in content:
                technologies['cms'] = 'WordPress'
                technologies['frameworks'].append('WordPress')
            
            # Joomla
            if '/components/com_' in content or 'Joomla' in content:
                technologies['cms'] = 'Joomla'
                technologies['frameworks'].append('Joomla')
            
            # Drupal
            if 'Drupal' in content or '/sites/default/' in content:
                technologies['cms'] = 'Drupal'
                technologies['frameworks'].append('Drupal')
            
            # JavaScript libraries
            if 'jquery' in content.lower():
                technologies['libraries'].append('jQuery')
            
            if 'react' in content.lower():
                technologies['libraries'].append('React')
            
            if 'angular' in content.lower():
                technologies['libraries'].append('Angular')
            
            if 'vue' in content.lower():
                technologies['libraries'].append('Vue.js')
            
        except Exception:
            pass
        
        return technologies
    
    def _get_security_headers(self):
        """Check security headers"""
        headers_check = {
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'Strict-Transport-Security': False,
            'Content-Security-Policy': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False
        }
        
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False
            )
            
            for header in headers_check.keys():
                if header in response.headers:
                    headers_check[header] = response.headers[header]
            
        except Exception:
            pass
        
        return headers_check
    
    def _analyze_ssl(self):
        """Analyze SSL/TLS configuration"""
        ssl_info = {
            'enabled': False,
            'version': None,
            'cipher': None,
            'certificate': {}
        }
        
        parsed = urlparse(self.target)
        if parsed.scheme != 'https':
            return ssl_info
        
        try:
            domain = self._get_domain()
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssl_info['enabled'] = True
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()[0]
                    
                    cert = ssock.getpeercert()
                    ssl_info['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception:
            pass
        
        return ssl_info
    
    def _detect_cms(self):
        """Detect CMS"""
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False
            )
            
            content = response.text.lower()
            headers = response.headers
            
            # WordPress
            if any(x in content for x in ['wp-content', 'wp-includes', 'wordpress']):
                return {
                    'name': 'WordPress',
                    'confidence': 'High'
                }
            
            # Joomla
            if any(x in content for x in ['/components/com_', 'joomla']):
                return {
                    'name': 'Joomla',
                    'confidence': 'High'
                }
            
            # Drupal
            if 'X-Drupal-Cache' in headers or 'drupal' in content:
                return {
                    'name': 'Drupal',
                    'confidence': 'High'
                }
            
            # Magento
            if 'mage' in content or 'magento' in content:
                return {
                    'name': 'Magento',
                    'confidence': 'Medium'
                }
            
            # Shopify
            if 'shopify' in content or 'cdn.shopify.com' in content:
                return {
                    'name': 'Shopify',
                    'confidence': 'High'
                }
            
            return None
            
        except Exception:
            return None
    
    def _detect_waf(self):
        """Detect Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Imperva': ['incap_ses', '_incap_', 'visid_incap'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Akamai': ['akamai', 'ak_bmsc'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Wordfence': ['wordfence'],
            'Barracuda': ['barra_counter_session']
        }
        
        detected_wafs = []
        
        try:
            response = requests.get(
                self.target,
                timeout=self.timeout,
                verify=False
            )
            
            headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            cookies_lower = response.cookies.get_dict()
            cookies_str = str(cookies_lower).lower()
            content_lower = response.text.lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    sig_lower = sig.lower()
                    if (sig_lower in str(headers_lower) or 
                        sig_lower in cookies_str or 
                        sig_lower in content_lower):
                        detected_wafs.append({
                            'name': waf_name,
                            'confidence': 'High'
                        })
                        break
            
        except Exception:
            pass
        
        return detected_wafs if detected_wafs else None
    
    def get_summary(self):
        """Get analysis summary"""
        if not self.info:
            self.analyze()
        
        summary = f"""
Target Analysis Summary:
========================
URL: {self.info.get('url')}
Domain: {self.info.get('domain')}
IP: {self.info.get('ip')}
Server: {self.info.get('server', {}).get('server', 'Unknown')}
CMS: {self.info.get('cms', {}).get('name', 'None') if self.info.get('cms') else 'None'}
WAF: {self.info.get('waf')[0].get('name') if self.info.get('waf') else 'None'}
SSL: {'Enabled' if self.info.get('ssl', {}).get('enabled') else 'Disabled'}
"""
        return summary
