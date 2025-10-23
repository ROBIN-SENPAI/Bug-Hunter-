"""
Race Condition Scanner
======================

Detects race condition vulnerabilities in concurrent operations like:
- Coupon/discount code abuse (use same code multiple times)
- Account balance manipulation
- Resource exhaustion
- Double spending attacks
- TOCTOU (Time-of-Check Time-of-Use) vulnerabilities

Author: ROBIN | @ll bUg
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class RaceConditionScanner:
    """
    Advanced scanner for detecting race condition vulnerabilities
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.results = []
        self.name = "Race Condition Scanner"
        self.description = "Detects race condition vulnerabilities"
        
        # Configuration
        self.threads = self.config.get('race_threads', 50)
        self.timeout = self.config.get('timeout', 30)
        self.delay = self.config.get('delay', 0.01)
        
    def scan(self, endpoints: List[str] = None) -> List[Dict]:
        """
        Main scanning function
        """
        print(f"[*] Starting Race Condition scan on {self.target}")
        
        # Test endpoints
        test_endpoints = endpoints or self._get_test_endpoints()
        
        for endpoint in test_endpoints:
            print(f"[*] Testing: {endpoint}")
            
            # Test different race condition scenarios
            self._test_coupon_race(endpoint)
            self._test_balance_race(endpoint)
            self._test_resource_race(endpoint)
            self._test_concurrent_modifications(endpoint)
            
        return self.results
    
    def _get_test_endpoints(self) -> List[str]:
        """
        Common endpoints vulnerable to race conditions
        """
        return [
            f"{self.target}/api/coupon/apply",
            f"{self.target}/api/payment/process",
            f"{self.target}/api/cart/checkout",
            f"{self.target}/api/discount/redeem",
            f"{self.target}/api/balance/withdraw",
            f"{self.target}/api/account/transfer",
            f"{self.target}/api/vote/submit",
            f"{self.target}/api/like/add",
            f"{self.target}/checkout",
            f"{self.target}/apply-coupon",
        ]
    
    def _test_coupon_race(self, url: str):
        """
        Test for coupon/discount code race condition
        Multiple requests use same coupon simultaneously
        """
        print(f"  [→] Testing coupon race condition...")
        
        # Test data
        payloads = [
            {"coupon": "SAVE50", "amount": 100},
            {"code": "DISCOUNT20", "total": 200},
            {"promo": "FREESHIP", "cart_id": 123},
        ]
        
        for payload in payloads:
            result = self._execute_concurrent_requests(
                url=url,
                method="POST",
                data=payload,
                num_requests=self.threads,
                test_name="Coupon Race Condition"
            )
            
            if result:
                self.results.append(result)
    
    def _test_balance_race(self, url: str):
        """
        Test for balance/credit race condition
        Multiple withdrawals from same account simultaneously
        """
        print(f"  [→] Testing balance race condition...")
        
        payloads = [
            {"amount": 100, "account": "12345"},
            {"withdraw": 50, "user_id": 1},
            {"transfer": 200, "from_account": 123, "to_account": 456},
        ]
        
        for payload in payloads:
            result = self._execute_concurrent_requests(
                url=url,
                method="POST",
                data=payload,
                num_requests=self.threads,
                test_name="Balance Race Condition"
            )
            
            if result:
                self.results.append(result)
    
    def _test_resource_race(self, url: str):
        """
        Test for resource exhaustion via race condition
        """
        print(f"  [→] Testing resource race condition...")
        
        result = self._execute_concurrent_requests(
            url=url,
            method="GET",
            num_requests=100,
            test_name="Resource Exhaustion Race"
        )
        
        if result:
            self.results.append(result)
    
    def _test_concurrent_modifications(self, url: str):
        """
        Test for concurrent modification issues (TOCTOU)
        """
        print(f"  [→] Testing concurrent modifications...")
        
        payloads = [
            {"action": "update", "id": 1, "value": "modified"},
            {"edit": True, "user_id": 123},
        ]
        
        for payload in payloads:
            result = self._execute_concurrent_requests(
                url=url,
                method="PUT",
                data=payload,
                num_requests=20,
                test_name="Concurrent Modification"
            )
            
            if result:
                self.results.append(result)
    
    def _execute_concurrent_requests(
        self, 
        url: str, 
        method: str = "GET",
        data: Dict = None,
        num_requests: int = 50,
        test_name: str = "Race Condition"
    ) -> Dict:
        """
        Execute multiple concurrent requests and analyze results
        """
        responses = []
        start_time = time.time()
        
        # Thread-safe counter
        success_count = threading.Lock()
        successful = []
        
        def send_request(request_id):
            try:
                import requests
                
                if method == "POST":
                    resp = requests.post(url, json=data, timeout=self.timeout)
                elif method == "PUT":
                    resp = requests.put(url, json=data, timeout=self.timeout)
                else:
                    resp = requests.get(url, timeout=self.timeout)
                
                with success_count:
                    successful.append({
                        'id': request_id,
                        'status': resp.status_code,
                        'time': time.time() - start_time,
                        'response': resp.text[:200]
                    })
                
                return resp
            except Exception as e:
                return None
        
        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(send_request, i) for i in range(num_requests)]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    responses.append(result)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Analyze results
        return self._analyze_race_results(
            url=url,
            test_name=test_name,
            responses=successful,
            duration=duration,
            expected_requests=num_requests
        )
    
    def _analyze_race_results(
        self, 
        url: str,
        test_name: str,
        responses: List[Dict],
        duration: float,
        expected_requests: int
    ) -> Dict:
        """
        Analyze concurrent request results for race conditions
        """
        success_responses = [r for r in responses if 200 <= r['status'] < 300]
        
        # Detection logic
        is_vulnerable = False
        evidence = []
        confidence = 0
        
        # Check 1: Too many successful responses (expected only 1)
        if len(success_responses) > 1:
            is_vulnerable = True
            confidence = 80
            evidence.append(f"Multiple successful responses: {len(success_responses)}/{expected_requests}")
        
        # Check 2: Look for duplicate actions in responses
        unique_responses = set(r['response'] for r in responses)
        if len(unique_responses) < len(responses) / 2:
            is_vulnerable = True
            confidence = min(confidence + 15, 95)
            evidence.append("Duplicate responses detected - possible race condition")
        
        # Check 3: Timing analysis (all requests completed too fast)
        if duration < 1.0 and len(success_responses) > 5:
            confidence = min(confidence + 10, 98)
            evidence.append(f"Suspiciously fast concurrent processing: {duration:.2f}s")
        
        if is_vulnerable:
            return {
                'vulnerability': test_name,
                'severity': 'HIGH',
                'confidence': confidence,
                'url': url,
                'method': 'Concurrent Requests',
                'evidence': evidence,
                'successful_races': len(success_responses),
                'total_requests': expected_requests,
                'duration': f"{duration:.2f}s",
                'impact': self._get_impact(test_name),
                'remediation': self._get_remediation(),
                'cvss_score': 8.1,
                'cwe': 'CWE-362'
            }
        
        return None
    
    async def _async_concurrent_test(
        self, 
        url: str, 
        method: str = "GET",
        data: Dict = None,
        num_requests: int = 50
    ):
        """
        Async version for even faster concurrent testing
        """
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            for i in range(num_requests):
                if method == "POST":
                    task = session.post(url, json=data, timeout=self.timeout)
                else:
                    task = session.get(url, timeout=self.timeout)
                
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            return responses
    
    def _get_impact(self, test_name: str) -> str:
        """
        Get impact description based on test type
        """
        impacts = {
            "Coupon Race Condition": "Attacker can apply same discount code multiple times, causing financial loss",
            "Balance Race Condition": "Attacker can withdraw more than available balance, causing monetary theft",
            "Resource Exhaustion Race": "Server resources can be exhausted leading to DoS",
            "Concurrent Modification": "Data corruption and inconsistent state possible"
        }
        return impacts.get(test_name, "Race condition allows unexpected behavior")
    
    def _get_remediation(self) -> str:
        """
        Get remediation advice
        """
        return """
        1. Implement proper locking mechanisms (database locks, mutexes)
        2. Use atomic operations for critical actions
        3. Implement idempotency keys for API requests
        4. Add request rate limiting per user/session
        5. Use database transactions with proper isolation levels
        6. Implement optimistic locking with version numbers
        7. Add duplicate request detection (nonce/token per request)
        
        Example (Python):
        ```python
        from threading import Lock
        
        lock = Lock()
        
        def apply_coupon(code, user):
            with lock:
                # Check if coupon already used
                if is_coupon_used(code, user):
                    return False
                
                # Mark as used atomically
                mark_coupon_used(code, user)
                return True
        ```
        """


# Example usage
if __name__ == "__main__":
    scanner = RaceConditionScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n[+] Found {len(results)} race condition vulnerabilities")
    for vuln in results:
        print(f"\n🔴 {vuln['vulnerability']}")
        print(f"   URL: {vuln['url']}")
        print(f"   Confidence: {vuln['confidence']}%")
        print(f"   Evidence: {', '.join(vuln['evidence'])}")
