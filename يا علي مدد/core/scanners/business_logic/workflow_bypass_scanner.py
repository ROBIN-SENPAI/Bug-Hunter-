"""
Workflow Bypass Scanner
=======================

Detects business logic flaws where attackers can bypass required workflow steps:
- Skipping payment verification
- Bypassing approval processes
- Skipping required steps in multi-step forms
- Direct access to final steps
- State manipulation
- Step sequence violations

Examples:
- Accessing order confirmation without payment
- Skipping email verification
- Bypassing two-factor authentication
- Direct access to download without purchase

Author: ROBIN | @ll bUg
"""

import requests
import json
from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode


class WorkflowBypassScanner:
    """
    Scanner for detecting workflow bypass vulnerabilities
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.results = []
        self.name = "Workflow Bypass Scanner"
        self.description = "Detects business process bypass vulnerabilities"
        
        self.timeout = self.config.get('timeout', 15)
        self.session = requests.Session()
        
    def scan(self, endpoints: List[str] = None) -> List[Dict]:
        """
        Main scanning function
        """
        print(f"[*] Starting Workflow Bypass scan on {self.target}")
        
        # Test different workflow bypass scenarios
        self._test_multi_step_bypass()
        self._test_payment_bypass()
        self._test_verification_bypass()
        self._test_approval_bypass()
        self._test_state_manipulation()
        self._test_direct_access()
        
        return self.results
    
    def _test_multi_step_bypass(self):
        """
        Test bypassing multi-step processes
        """
        print(f"  [→] Testing multi-step process bypass...")
        
        # Common multi-step workflows
        workflows = [
            # Registration workflow
            {
                'name': 'Registration Workflow',
                'steps': [
                    {'url': f'{self.target}/register', 'step': 1},
                    {'url': f'{self.target}/verify-email', 'step': 2},
                    {'url': f'{self.target}/complete-profile', 'step': 3},
                    {'url': f'{self.target}/dashboard', 'step': 4},  # Final step
                ]
            },
            # Checkout workflow
            {
                'name': 'Checkout Workflow',
                'steps': [
                    {'url': f'{self.target}/cart', 'step': 1},
                    {'url': f'{self.target}/checkout', 'step': 2},
                    {'url': f'{self.target}/payment', 'step': 3},
                    {'url': f'{self.target}/confirmation', 'step': 4},  # Final step
                ]
            },
            # Course enrollment
            {
                'name': 'Course Enrollment',
                'steps': [
                    {'url': f'{self.target}/course/preview', 'step': 1},
                    {'url': f'{self.target}/course/enroll', 'step': 2},
                    {'url': f'{self.target}/course/payment', 'step': 3},
                    {'url': f'{self.target}/course/access', 'step': 4},  # Final step
                ]
            }
        ]
        
        for workflow in workflows:
            print(f"    Testing: {workflow['name']}")
            
            # Try to access final step without going through previous steps
            final_step = workflow['steps'][-1]
            
            result = self._attempt_step_skip(
                workflow_name=workflow['name'],
                steps=workflow['steps'],
                target_step=final_step
            )
            
            if result:
                self.results.append(result)
    
    def _test_payment_bypass(self):
        """
        Test bypassing payment verification
        """
        print(f"  [→] Testing payment bypass...")
        
        # Common payment bypass scenarios
        test_cases = [
            {
                'name': 'Direct Order Confirmation',
                'url': f'{self.target}/order/confirmation',
                'params': {'order_id': '12345'}
            },
            {
                'name': 'Direct Download Access',
                'url': f'{self.target}/download',
                'params': {'file_id': '123', 'product_id': '456'}
            },
            {
                'name': 'Direct Premium Content',
                'url': f'{self.target}/premium/content',
                'params': {'content_id': '789'}
            },
            {
                'name': 'API Premium Endpoint',
                'url': f'{self.target}/api/premium/data',
                'params': {}
            }
        ]
        
        for test_case in test_cases:
            result = self._test_direct_access(
                name=test_case['name'],
                url=test_case['url'],
                params=test_case['params']
            )
            
            if result:
                self.results.append(result)
    
    def _test_verification_bypass(self):
        """
        Test bypassing verification steps
        """
        print(f"  [→] Testing verification bypass...")
        
        # Email verification bypass
        verification_tests = [
            {
                'name': 'Email Verification Bypass',
                'url': f'{self.target}/account/settings',
                'expected_redirect': '/verify-email'
            },
            {
                'name': 'Phone Verification Bypass',
                'url': f'{self.target}/secure/action',
                'expected_redirect': '/verify-phone'
            },
            {
                'name': '2FA Bypass',
                'url': f'{self.target}/dashboard',
                'expected_redirect': '/two-factor'
            },
            {
                'name': 'KYC Bypass',
                'url': f'{self.target}/withdraw',
                'expected_redirect': '/verify-identity'
            }
        ]
        
        for test in verification_tests:
            # Try to access protected page without verification
            try:
                response = self.session.get(
                    test['url'],
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                # If we get 200 OK instead of redirect, verification is bypassed
                if response.status_code == 200:
                    confidence = 85
                    evidence = [
                        f"Direct access allowed with status {response.status_code}",
                        f"Expected redirect to {test['expected_redirect']} but got 200 OK"
                    ]
                    
                    # Check response content
                    if any(keyword in response.text.lower() for keyword in ['dashboard', 'welcome', 'account', 'settings']):
                        confidence = 95
                        evidence.append("Protected content accessible without verification")
                    
                    self.results.append({
                        'vulnerability': f'Workflow Bypass - {test["name"]}',
                        'severity': 'HIGH',
                        'confidence': confidence,
                        'url': test['url'],
                        'method': 'GET',
                        'evidence': evidence,
                        'response_code': response.status_code,
                        'impact': 'Users can access protected features without completing verification',
                        'remediation': self._get_remediation(),
                        'cvss_score': 7.5,
                        'cwe': 'CWE-841'
                    })
                    
            except:
                pass
    
    def _test_approval_bypass(self):
        """
        Test bypassing approval processes
        """
        print(f"  [→] Testing approval bypass...")
        
        approval_tests = [
            # Try to directly approve without authorization
            {
                'url': f'{self.target}/api/approve',
                'method': 'POST',
                'data': {'request_id': 123, 'status': 'approved'}
            },
            {
                'url': f'{self.target}/admin/approve',
                'method': 'POST',
                'data': {'id': 456, 'approve': True}
            },
            # Try to change status directly
            {
                'url': f'{self.target}/api/request/update',
                'method': 'PUT',
                'data': {'id': 789, 'status': 'approved'}
            }
        ]
        
        for test in approval_tests:
            try:
                if test['method'] == 'POST':
                    response = self.session.post(
                        test['url'],
                        json=test['data'],
                        timeout=self.timeout
                    )
                else:
                    response = self.session.put(
                        test['url'],
                        json=test['data'],
                        timeout=self.timeout
                    )
                
                # Analyze response
                if 200 <= response.status_code < 300:
                    response_text = response.text.lower()
                    
                    success_indicators = ['success', 'approved', 'completed', 'updated']
                    if any(indicator in response_text for indicator in success_indicators):
                        self.results.append({
                            'vulnerability': 'Workflow Bypass - Approval Process',
                            'severity': 'CRITICAL',
                            'confidence': 90,
                            'url': test['url'],
                            'method': test['method'],
                            'payload': json.dumps(test['data'], indent=2),
                            'evidence': [
                                f"Direct approval possible with status {response.status_code}",
                                "Success indicator found in response"
                            ],
                            'response_code': response.status_code,
                            'impact': 'Unauthorized users can approve critical requests',
                            'remediation': self._get_remediation(),
                            'cvss_score': 9.0,
                            'cwe': 'CWE-841'
                        })
                        
            except:
                pass
    
    def _test_state_manipulation(self):
        """
        Test state manipulation to bypass workflow
        """
        print(f"  [→] Testing state manipulation...")
        
        # Try to manipulate session/state parameters
        state_tests = [
            {'step': 4, 'completed': True},
            {'current_step': 'final'},
            {'workflow_stage': 'completed'},
            {'payment_verified': True},
            {'email_verified': True},
            {'approved': True},
            {'status': 'active'},
            {'is_premium': True},
        ]
        
        test_url = f'{self.target}/api/checkout'
        
        for state_data in state_tests:
            try:
                # Try to manipulate state via request
                response = self.session.post(
                    test_url,
                    json=state_data,
                    timeout=self.timeout
                )
                
                if self._is_bypass_successful(response):
                    self.results.append({
                        'vulnerability': 'Workflow Bypass - State Manipulation',
                        'severity': 'HIGH',
                        'confidence': 85,
                        'url': test_url,
                        'method': 'POST',
                        'payload': json.dumps(state_data, indent=2),
                        'evidence': ['State manipulation accepted', 'Workflow step bypassed'],
                        'response_code': response.status_code,
                        'impact': 'Attacker can manipulate workflow state to bypass security controls',
                        'remediation': self._get_remediation(),
                        'cvss_score': 8.0,
                        'cwe': 'CWE-841'
                    })
                    return  # Found vulnerability
                    
            except:
                pass
    
    def _test_direct_access(self):
        """
        Test direct access to protected endpoints
        """
        print(f"  [→] Testing direct access to protected endpoints...")
        
        protected_endpoints = [
            f'{self.target}/admin/dashboard',
            f'{self.target}/api/admin/users',
            f'{self.target}/download/premium',
            f'{self.target}/api/premium/content',
            f'{self.target}/invoice/generate',
            f'{self.target}/report/export',
            f'{self.target}/api/order/complete',
            f'{self.target}/subscription/activate',
        ]
        
        for url in protected_endpoints:
            result = self._test_direct_access(
                name='Direct Protected Access',
                url=url,
                params={}
            )
            
            if result:
                self.results.append(result)
    
    def _attempt_step_skip(
        self,
        workflow_name: str,
        steps: List[Dict],
        target_step: Dict
    ) -> Dict:
        """
        Attempt to skip workflow steps and access final step directly
        """
        try:
            # Try to access final step without previous steps
            response = self.session.get(
                target_step['url'],
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Check if access was granted
            if response.status_code == 200:
                evidence = [
                    f"Direct access to step {target_step['step']} allowed",
                    "No redirect to previous steps",
                    f"HTTP {response.status_code} OK received"
                ]
                
                # Additional checks
                response_text = response.text.lower()
                
                # Check for success indicators
                success_keywords = [
                    'success', 'complete', 'confirmed', 'thank you',
                    'dashboard', 'welcome', 'account created'
                ]
                
                if any(keyword in response_text for keyword in success_keywords):
                    evidence.append("Success indicators found in response")
                    confidence = 95
                else:
                    confidence = 80
                
                return {
                    'vulnerability': f'Workflow Bypass - {workflow_name}',
                    'severity': 'HIGH',
                    'confidence': confidence,
                    'url': target_step['url'],
                    'method': 'GET',
                    'evidence': evidence,
                    'response_code': response.status_code,
                    'bypassed_steps': [s['step'] for s in steps[:-1]],
                    'impact': f'Users can skip critical workflow steps in {workflow_name}',
                    'remediation': self._get_remediation(),
                    'cvss_score': 7.8,
                    'cwe': 'CWE-841'
                }
            
            # Check if redirect but still accessible via parameter manipulation
            elif response.status_code in [301, 302, 303, 307, 308]:
                # Try with different parameters
                test_params = [
                    {'skip': 'true'},
                    {'force': '1'},
                    {'bypass': 'true'},
                    {'step': target_step['step']},
                    {'completed': 'true'},
                ]
                
                for params in test_params:
                    response2 = self.session.get(
                        target_step['url'],
                        params=params,
                        timeout=self.timeout
                    )
                    
                    if response2.status_code == 200:
                        return {
                            'vulnerability': f'Workflow Bypass - {workflow_name} (Parameter)',
                            'severity': 'HIGH',
                            'confidence': 90,
                            'url': target_step['url'],
                            'method': 'GET',
                            'parameters': params,
                            'evidence': [
                                f"Bypass via parameters: {params}",
                                f"Direct access granted with status {response2.status_code}"
                            ],
                            'response_code': response2.status_code,
                            'impact': f'Workflow can be bypassed using URL parameters',
                            'remediation': self._get_remediation(),
                            'cvss_score': 7.8,
                            'cwe': 'CWE-841'
                        }
                        
        except:
            pass
        
        return None
    
    def _test_direct_access(
        self,
        name: str,
        url: str,
        params: Dict
    ) -> Dict:
        """
        Test direct access to protected resources
        """
        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            if self._is_bypass_successful(response):
                return {
                    'vulnerability': f'Workflow Bypass - {name}',
                    'severity': 'HIGH',
                    'confidence': 85,
                    'url': url,
                    'method': 'GET',
                    'parameters': params if params else None,
                    'evidence': self._extract_evidence(response),
                    'response_code': response.status_code,
                    'impact': 'Protected resources accessible without proper authorization',
                    'remediation': self._get_remediation(),
                    'cvss_score': 7.5,
                    'cwe': 'CWE-841'
                }
                
        except:
            pass
        
        return None
    
    def _is_bypass_successful(self, response: requests.Response) -> bool:
        """
        Determine if workflow bypass was successful
        """
        # Check status code
        if response.status_code != 200:
            return False
        
        response_text = response.text.lower()
        
        # Success indicators
        success_indicators = [
            'success', 'confirmed', 'complete', 'approved',
            'thank you', 'congratulations', 'welcome',
            'download', 'access granted', 'activated'
        ]
        
        # Failure indicators (if present, bypass failed)
        failure_indicators = [
            'unauthorized', 'forbidden', 'access denied',
            'permission denied', 'not authorized', 'login required',
            'payment required', 'verification required'
        ]
        
        # Check for failure first
        if any(indicator in response_text for indicator in failure_indicators):
            return False
        
        # Check for success
        if any(indicator in response_text for indicator in success_indicators):
            return True
        
        # Check response length (empty responses are likely failures)
        if len(response.text) > 100:
            return True
        
        return False
    
    def _extract_evidence(self, response: requests.Response) -> List[str]:
        """
        Extract evidence from response
        """
        evidence = [f"HTTP {response.status_code} OK"]
        
        response_text = response.text.lower()
        
        # Look for specific evidence
        if 'dashboard' in response_text:
            evidence.append("Dashboard content accessible")
        
        if 'download' in response_text:
            evidence.append("Download functionality accessible")
        
        if 'premium' in response_text or 'pro' in response_text:
            evidence.append("Premium content accessible")
        
        if 'admin' in response_text:
            evidence.append("Admin interface accessible")
        
        # Check for data in response
        try:
            json_data = response.json()
            if json_data:
                evidence.append("Protected data returned in JSON response")
        except:
            pass
        
        return evidence
    
    def _get_remediation(self) -> str:
        """
        Get remediation advice
        """
        return """
        1. Implement server-side workflow state management
        2. Never trust client-side state/step tracking
        3. Use server-side sessions to track workflow progress
        4. Validate that all required steps were completed before allowing access
        5. Implement proper authorization checks at each step
        6. Use cryptographically signed tokens to track workflow state
        7. Log and monitor workflow violations
        
        Example (Python/Flask):
        ```python
        from flask import session, redirect, url_for
        
        @app.route('/checkout')
        def checkout():
            # Verify previous steps completed
            if not session.get('cart_reviewed'):
                return redirect(url_for('cart'))
            
            if not session.get('shipping_entered'):
                return redirect(url_for('shipping'))
            
            # All steps completed, proceed
            return render_template('checkout.html')
        
        @app.route('/confirmation')
        def confirmation():
            # Verify payment completed
            if not session.get('payment_verified'):
                return redirect(url_for('payment'))
            
            # Clear session to prevent replay
            session.pop('payment_verified', None)
            
            return render_template('confirmation.html')
        ```
        
        Example (Node.js/Express):
        ```javascript
        // Middleware to check workflow state
        function requireStep(requiredSteps) {
            return (req, res, next) => {
                const completedSteps = req.session.completedSteps || [];
                
                const allStepsCompleted = requiredSteps.every(
                    step => completedSteps.includes(step)
                );
                
                if (!allStepsCompleted) {
                    return res.redirect('/workflow/start');
                }
                
                next();
            };
        }
        
        // Protected route
        app.get('/confirmation', 
            requireStep(['cart', 'shipping', 'payment']),
            (req, res) => {
                res.render('confirmation');
            }
        );
        ```
        """


# Example usage
if __name__ == "__main__":
    scanner = WorkflowBypassScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n[+] Found {len(results)} workflow bypass vulnerabilities")
    for vuln in results:
        print(f"\n🔴 {vuln['vulnerability']}")
        print(f"   URL: {vuln['url']}")
        print(f"   Severity: {vuln['severity']}")
        print(f"   Confidence: {vuln['confidence']}%")
        print(f"   Impact: {vuln['impact']}")
