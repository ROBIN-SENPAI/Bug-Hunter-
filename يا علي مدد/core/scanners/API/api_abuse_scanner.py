#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════╗
║           API Abuse & Rate Limiting Scanner                  ║
║              Part of AlBaTTaR BUGS Framework                 ║
╚══════════════════════════════════════════════════════════════╝

Description: Detects API abuse vulnerabilities and missing rate limiting

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

import requests
import time
import statistics
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

class APIAbuseScanner:
    """Scanner for API abuse and rate limiting vulnerabilities"""
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize API Abuse Scanner
        
        Args:
            target: Target API endpoint
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Configuration
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.max_threads = self.config.get('max_threads', 20)
        self.test_requests = self.config.get('test_requests', 100)
        
        # Rate limit headers to check
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'Retry-After'
        ]
        
    def scan(self) -> List[Dict]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        print(f"[*] Starting API Abuse scan on: {self.target}")
        
        # Test different abuse scenarios
        self._test_rate_limiting()
        self._test_resource_exhaustion()
        self._test_concurrent_requests()
        self._test_cost_exploitation()
        self._test_brute_force_protection()
        self._test_api_flooding()
        
        print(f"[+] Scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def _test_rate_limiting(self):
        """Test for missing or weak rate limiting"""
        print("[*] Testing rate limiting...")
        
        try:
            # Send rapid requests
            responses = []
            start_time = time.time()
            
            for i in range(self.test_requests):
                try:
                    response = self.session.get(
                        self.target,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    responses.append({
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'time': time.time() - start_time
                    })
                    
                    # Check for rate limit headers
                    if i == 0:
                        has_rate_limit = any(
                            header in response.headers 
                            for header in self.rate_limit_headers
                        )
                        if not has_rate_limit:
                            print("[!] No rate limit headers detected")
                    
                except Exception as e:
                    print(f"[!] Request {i} failed: {str(e)}")
                    continue
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Analyze results
            success_count = sum(1 for r in responses if r['status_code'] == 200)
            blocked_count = sum(1 for r in responses if r['status_code'] == 429)
            
            requests_per_second = len(responses) / duration if duration > 0 else 0
            
            print(f"[*] Sent {len(responses)} requests in {duration:.2f}s")
            print(f"[*] Success: {success_count}, Blocked: {blocked_count}")
            print(f"[*] Rate: {requests_per_second:.2f} requests/second")
            
            # Check if rate limiting is effective
            if success_count > self.test_requests * 0.8:  # More than 80% succeeded
                self.vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'high',
                    'url': self.target,
                    'description': 'API endpoint lacks proper rate limiting',
                    'evidence': {
                        'total_requests': len(responses),
                        'successful_requests': success_count,
                        'blocked_requests': blocked_count,
                        'requests_per_second': round(requests_per_second, 2),
                        'duration': round(duration, 2)
                    },
                    'impact': 'Attackers can perform brute force, DoS, or resource exhaustion attacks',
                    'remediation': 'Implement rate limiting (e.g., 100 requests per minute per IP)',
                    'cwe': 'CWE-770',
                    'confidence': 95
                })
                
        except Exception as e:
            print(f"[!] Error testing rate limiting: {str(e)}")
    
    def _test_resource_exhaustion(self):
        """Test for resource exhaustion vulnerabilities"""
        print("[*] Testing resource exhaustion...")
        
        try:
            # Test with large payloads
            large_payload = 'A' * (1024 * 1024)  # 1MB
            
            test_cases = [
                {'data': large_payload, 'name': 'large_payload'},
                {'json': {'data': large_payload}, 'name': 'large_json'},
                {'params': {'q': 'A' * 10000}, 'name': 'large_params'}
            ]
            
            for test_case in test_cases:
                name = test_case.pop('name')
                
                try:
                    response = self.session.post(
                        self.target,
                        timeout=self.timeout * 2,
                        verify=self.verify_ssl,
                        **test_case
                    )
                    
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Resource Exhaustion',
                            'severity': 'medium',
                            'url': self.target,
                            'test_case': name,
                            'description': f'API accepts large payloads without restrictions ({name})',
                            'impact': 'Can lead to DoS through memory/CPU exhaustion',
                            'remediation': 'Implement payload size limits and validation',
                            'cwe': 'CWE-400',
                            'confidence': 75
                        })
                        print(f"[!] Vulnerable to {name}")
                        
                except Exception as e:
                    print(f"[*] Test {name} failed: {str(e)}")
                    
        except Exception as e:
            print(f"[!] Error testing resource exhaustion: {str(e)}")
    
    def _test_concurrent_requests(self):
        """Test handling of concurrent requests"""
        print("[*] Testing concurrent request handling...")
        
        try:
            # Send concurrent requests
            concurrent_count = 50
            
            def make_request(i):
                try:
                    start = time.time()
                    response = self.session.get(
                        self.target,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    duration = time.time() - start
                    return {
                        'id': i,
                        'status': response.status_code,
                        'duration': duration,
                        'success': response.status_code == 200
                    }
                except Exception as e:
                    return {
                        'id': i,
                        'status': 0,
                        'duration': 0,
                        'success': False,
                        'error': str(e)
                    }
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(make_request, i) for i in range(concurrent_count)]
                results = [future.result() for future in as_completed(futures)]
            
            # Analyze results
            success_count = sum(1 for r in results if r['success'])
            avg_duration = statistics.mean([r['duration'] for r in results if r['duration'] > 0])
            
            print(f"[*] Concurrent requests: {success_count}/{concurrent_count} succeeded")
            print(f"[*] Average response time: {avg_duration:.2f}s")
            
            if success_count == concurrent_count:
                self.vulnerabilities.append({
                    'type': 'Concurrent Request Abuse',
                    'severity': 'medium',
                    'url': self.target,
                    'description': 'API handles unlimited concurrent requests without throttling',
                    'evidence': {
                        'concurrent_requests': concurrent_count,
                        'successful_requests': success_count,
                        'average_duration': round(avg_duration, 2)
                    },
                    'impact': 'Can lead to race conditions and resource exhaustion',
                    'remediation': 'Implement connection limiting and request queuing',
                    'cwe': 'CWE-770',
                    'confidence': 80
                })
                
        except Exception as e:
            print(f"[!] Error testing concurrent requests: {str(e)}")
    
    def _test_cost_exploitation(self):
        """Test for cost exploitation in paid APIs"""
        print("[*] Testing cost exploitation...")
        
        try:
            # Test expensive operations
            expensive_operations = [
                {'operation': 'bulk_export', 'params': {'limit': 999999}},
                {'operation': 'compute_intensive', 'params': {'iterations': 999999}},
                {'operation': 'data_processing', 'params': {'size': 'large'}}
            ]
            
            for op in expensive_operations:
                try:
                    response = self.session.post(
                        self.target,
                        json=op,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        print(f"[!] Expensive operation accepted: {op['operation']}")
                        self.vulnerabilities.append({
                            'type': 'Cost Exploitation',
                            'severity': 'high',
                            'url': self.target,
                            'operation': op['operation'],
                            'description': f'API accepts expensive operation without cost limits: {op["operation"]}',
                            'impact': 'Attacker can incur high costs or exhaust quota',
                            'remediation': 'Implement cost-based rate limiting and operation quotas',
                            'cwe': 'CWE-400',
                            'confidence': 70
                        })
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"[!] Error testing cost exploitation: {str(e)}")
    
    def _test_brute_force_protection(self):
        """Test brute force protection on authentication endpoints"""
        print("[*] Testing brute force protection...")
        
        # Check if this is an auth endpoint
        auth_indicators = ['login', 'auth', 'signin', 'token', 'password']
        is_auth_endpoint = any(indicator in self.target.lower() for indicator in auth_indicators)
        
        if not is_auth_endpoint:
            print("[*] Not an authentication endpoint, skipping")
            return
        
        try:
            # Attempt multiple failed logins
            failed_attempts = 0
            
            for i in range(20):  # Try 20 times
                try:
                    response = self.session.post(
                        self.target,
                        json={
                            'username': f'user{i}',
                            'password': 'wrongpassword'
                        },
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code in [401, 403]:
                        failed_attempts += 1
                    elif response.status_code == 429:  # Rate limited
                        print("[+] Brute force protection detected (429 response)")
                        return
                    
                except Exception as e:
                    continue
            
            # If all attempts succeeded without blocking
            if failed_attempts >= 15:
                self.vulnerabilities.append({
                    'type': 'Missing Brute Force Protection',
                    'severity': 'high',
                    'url': self.target,
                    'description': 'Authentication endpoint lacks brute force protection',
                    'evidence': {
                        'failed_attempts': failed_attempts,
                        'no_blocking': True
                    },
                    'impact': 'Attackers can perform credential stuffing or brute force attacks',
                    'remediation': 'Implement account lockout, CAPTCHA, or progressive delays',
                    'cwe': 'CWE-307',
                    'confidence': 90
                })
                
        except Exception as e:
            print(f"[!] Error testing brute force protection: {str(e)}")
    
    def _test_api_flooding(self):
        """Test API flooding resistance"""
        print("[*] Testing API flooding resistance...")
        
        try:
            # Send burst of requests
            burst_size = 50
            burst_interval = 0.01  # 10ms between requests
            
            responses = []
            for i in range(burst_size):
                try:
                    response = self.session.get(
                        self.target,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    responses.append(response.status_code)
                    time.sleep(burst_interval)
                except Exception as e:
                    responses.append(0)
            
            success_rate = responses.count(200) / len(responses)
            
            if success_rate > 0.9:  # More than 90% succeeded
                self.vulnerabilities.append({
                    'type': 'API Flooding Vulnerability',
                    'severity': 'medium',
                    'url': self.target,
                    'description': 'API vulnerable to flooding attacks',
                    'evidence': {
                        'burst_size': burst_size,
                        'success_rate': round(success_rate * 100, 2)
                    },
                    'impact': 'Can be used for DoS attacks',
                    'remediation': 'Implement burst rate limiting',
                    'cwe': 'CWE-400',
                    'confidence': 75
                })
                
        except Exception as e:
            print(f"[!] Error testing API flooding: {str(e)}")


# Example usage
if __name__ == "__main__":
    # Configuration
    config = {
        'timeout': 10,
        'verify_ssl': False,
        'max_threads': 20,
        'test_requests': 100
    }
    
    # Initialize scanner
    target = "https://api.example.com/endpoint"
    scanner = APIAbuseScanner(target, config)
    
    # Run scan
    vulnerabilities = scanner.scan()
    
    # Display results
    print("\n" + "="*60)
    print("API ABUSE SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"\n[{vuln['severity'].upper()}] {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Description: {vuln['description']}")
            print(f"Impact: {vuln['impact']}")
            print(f"Confidence: {vuln['confidence']}%")
            if 'evidence' in vuln:
                print(f"Evidence: {json.dumps(vuln['evidence'], indent=2)}")
    else:
        print("\n[+] No vulnerabilities found!")
