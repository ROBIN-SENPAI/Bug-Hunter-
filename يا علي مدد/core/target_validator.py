"""
Target Validator - Validates and checks targets before scanning
"""

import re
import socket
import requests
from urllib.parse import urlparse
from pathlib import Path
import validators
import dns.resolver


class TargetValidator:
    """Validate targets before scanning"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.scope_file = self.config.get('scope', {}).get('scope_file', 'scope.txt')
        self.strict_scope = self.config.get('scope', {}).get('strict_scope', True)
        self.allowed_domains = self._load_scope()
        
    def validate(self, target):
        """Main validation method"""
        try:
            # Normalize target
            target = self._normalize_target(target)
            
            # Basic format validation
            if not self._is_valid_format(target):
                return False
            
            # Scope validation
            if self.strict_scope and not self._is_in_scope(target):
                print(f"❌ Target {target} is out of scope!")
                return False
            
            # Check if target is reachable
            if not self._is_reachable(target):
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Validation error: {e}")
            return False
    
    def _normalize_target(self, target):
        """Normalize target URL"""
        target = target.strip()
        
        # Add http:// if no scheme
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        return target
    
    def _is_valid_format(self, target):
        """Check if target has valid format"""
        # Validate URL format
        if not validators.url(target):
            print(f"❌ Invalid URL format: {target}")
            return False
        
        # Parse URL
        parsed = urlparse(target)
        
        # Check if domain is valid
        if not parsed.netloc:
            print(f"❌ Invalid domain: {target}")
            return False
        
        return True
    
    def _is_in_scope(self, target):
        """Check if target is in scope"""
        if not self.allowed_domains:
            return True  # No scope file, allow all
        
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Check exact match
        if domain in self.allowed_domains:
            return True
        
        # Check wildcard subdomains
        for allowed in self.allowed_domains:
            if allowed.startswith('*.'):
                parent_domain = allowed[2:]
                if domain.endswith(parent_domain):
                    return True
        
        return False
    
    def _is_reachable(self, target):
        """Check if target is reachable"""
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # DNS resolution check
        try:
            dns.resolver.resolve(domain, 'A')
        except Exception:
            print(f"❌ DNS resolution failed for: {domain}")
            return False
        
        # HTTP connectivity check
        try:
            response = requests.get(
                target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return True
        except requests.exceptions.RequestException as e:
            print(f"❌ Target unreachable: {e}")
            return False
    
    def _load_scope(self):
        """Load scope from file"""
        scope_path = Path(self.scope_file)
        
        if not scope_path.exists():
            return []
        
        try:
            with open(scope_path, 'r') as f:
                domains = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
                return domains
        except Exception as e:
            print(f"⚠️  Error loading scope file: {e}")
            return []
    
    def is_ip_address(self, target):
        """Check if target is an IP address"""
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0]
        
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            return True
        
        # IPv6 check
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            return True
        except socket.error:
            return False
    
    def extract_domain(self, target):
        """Extract domain from target"""
        parsed = urlparse(target)
        domain = parsed.netloc
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def get_base_url(self, target):
        """Get base URL from target"""
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
