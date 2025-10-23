"""
Payment Logic Scanner
=====================

Detects payment logic flaws and vulnerabilities:
- Price manipulation (client-side price modification)
- Negative amounts (refund abuse)
- Currency manipulation
- Discount/coupon abuse
- Tax evasion
- Rounding errors exploitation
- Free premium access
- Payment bypass

Author: ROBIN | @ll bUg
"""

import requests
import json
from typing import List, Dict, Any
from decimal import Decimal
import re


class PaymentLogicScanner:
    """
    Scanner for detecting payment logic vulnerabilities
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.results = []
        self.name = "Payment Logic Scanner"
        self.description = "Detects payment logic vulnerabilities"
        
        self.timeout = self.config.get('timeout', 15)
        self.test_amounts = self._get_test_amounts()
        
    def scan(self, endpoints: List[str] = None) -> List[Dict]:
        """
        Main scanning function
        """
        print(f"[*] Starting Payment Logic scan on {self.target}")
        
        # Get test endpoints
        test_endpoints = endpoints or self._get_test_endpoints()
        
        for endpoint in test_endpoints:
            print(f"[*] Testing: {endpoint}")
            
            # Test different payment logic flaws
            self._test_price_manipulation(endpoint)
            self._test_negative_amounts(endpoint)
            self._test_currency_manipulation(endpoint)
            self._test_discount_abuse(endpoint)
            self._test_tax_evasion(endpoint)
            self._test_rounding_errors(endpoint)
            self._test_payment_bypass(endpoint)
            self._test_quantity_manipulation(endpoint)
            
        return self.results
    
    def _get_test_endpoints(self) -> List[str]:
        """
        Common payment endpoints
        """
        return [
            f"{self.target}/api/checkout",
            f"{self.target}/api/payment/process",
            f"{self.target}/api/order/create",
            f"{self.target}/api/cart/checkout",
            f"{self.target}/api/purchase",
            f"{self.target}/checkout",
            f"{self.target}/payment",
            f"{self.target}/order/place",
            f"{self.target}/buy",
            f"{self.target}/api/subscription/upgrade",
        ]
    
    def _get_test_amounts(self) -> List[Dict]:
        """
        Test amounts and scenarios
        """
        return [
            {'amount': 0, 'description': 'Zero amount'},
            {'amount': 0.01, 'description': 'Minimal amount'},
            {'amount': -100, 'description': 'Negative amount'},
            {'amount': -0.01, 'description': 'Negative minimal'},
            {'amount': 999999999, 'description': 'Overflow amount'},
            {'amount': '0', 'description': 'String zero'},
            {'amount': 'null', 'description': 'Null string'},
            {'amount': None, 'description': 'None value'},
            {'amount': '', 'description': 'Empty string'},
        ]
    
    def _test_price_manipulation(self, url: str):
        """
        Test for client-side price manipulation
        """
        print(f"  [→] Testing price manipulation...")
        
        # Test with different price fields
        price_fields = ['price', 'amount', 'total', 'cost', 'final_price', 'product_price']
        
        for field in price_fields:
            for test_case in self._get_test_amounts():
                payload = {
                    'product_id': 123,
                    'quantity': 1,
                    field: test_case['amount']
                }
                
                result = self._send_payment_request(
                    url=url,
                    payload=payload,
                    test_type="Price Manipulation",
                    test_description=f"{field} = {test_case['description']}"
                )
                
                if result:
                    self.results.append(result)
                    return  # Found vulnerability
    
    def _test_negative_amounts(self, url: str):
        """
        Test for negative amount acceptance (refund abuse)
        """
        print(f"  [→] Testing negative amounts...")
        
        negative_tests = [
            {'amount': -100, 'currency': 'USD'},
            {'price': -50.00, 'quantity': 1},
            {'total': -1000, 'discount': 0},
            {'subtotal': 100, 'discount': 200},  # Discount > subtotal
        ]
        
        for payload in negative_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Negative Amount Acceptance",
                test_description="Negative payment amount"
            )
            
            if result:
                self.results.append(result)
    
    def _test_currency_manipulation(self, url: str):
        """
        Test for currency manipulation vulnerabilities
        """
        print(f"  [→] Testing currency manipulation...")
        
        # Test currency switching to cheaper currencies
        currency_tests = [
            {'amount': 100, 'currency': 'USD', 'original_currency': 'EUR'},
            {'price': 1000, 'currency': 'IDR'},  # Indonesian Rupiah (very cheap)
            {'total': 100, 'currency': 'VND'},   # Vietnamese Dong
            {'amount': 100, 'currency': 'XXX'},  # Invalid currency
            {'price': 100, 'currency': ''},      # Empty currency
        ]
        
        for payload in currency_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Currency Manipulation",
                test_description=f"Currency: {payload.get('currency')}"
            )
            
            if result:
                self.results.append(result)
    
    def _test_discount_abuse(self, url: str):
        """
        Test for discount/coupon abuse
        """
        print(f"  [→] Testing discount abuse...")
        
        discount_tests = [
            {'amount': 100, 'discount': 100},     # 100% discount
            {'price': 100, 'discount': 150},      # Discount > price
            {'total': 100, 'discount': 999999},   # Huge discount
            {'amount': 100, 'discount_percent': 100},
            {'price': 100, 'coupon_value': 200},
            {'total': 100, 'promo_discount': -50}, # Negative discount (add to price?)
        ]
        
        for payload in discount_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Discount Abuse",
                test_description="Excessive discount"
            )
            
            if result:
                self.results.append(result)
    
    def _test_tax_evasion(self, url: str):
        """
        Test for tax evasion vulnerabilities
        """
        print(f"  [→] Testing tax evasion...")
        
        tax_tests = [
            {'amount': 100, 'tax': 0},
            {'price': 100, 'tax_rate': 0},
            {'total': 100, 'tax': -10},        # Negative tax
            {'amount': 100, 'tax_exempt': True},
            {'price': 100, 'vat': 0},
            {'subtotal': 100, 'tax_included': False, 'tax': 0},
        ]
        
        for payload in tax_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Tax Evasion",
                test_description="Tax manipulation"
            )
            
            if result:
                self.results.append(result)
    
    def _test_rounding_errors(self, url: str):
        """
        Test for rounding error exploitation
        """
        print(f"  [→] Testing rounding errors...")
        
        # Small fractional amounts that might be rounded to zero
        rounding_tests = [
            {'amount': 0.001, 'quantity': 1000},   # Might round to 0
            {'price': 0.004, 'quantity': 100},
            {'amount': 0.0001, 'currency': 'BTC'}, # Cryptocurrency
            {'price': Decimal('0.00001')},
        ]
        
        for payload in rounding_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Rounding Error Exploitation",
                test_description="Fractional amounts"
            )
            
            if result:
                self.results.append(result)
    
    def _test_payment_bypass(self, url: str):
        """
        Test for payment bypass vulnerabilities
        """
        print(f"  [→] Testing payment bypass...")
        
        bypass_tests = [
            {'paid': True, 'amount': 0},
            {'payment_status': 'completed', 'amount': 0},
            {'is_paid': 1, 'price': 0},
            {'payment_verified': True},
            {'transaction_id': 'fake123', 'status': 'success'},
            {'payment_method': 'free', 'amount': 100},
            {'skip_payment': True},
        ]
        
        for payload in bypass_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Payment Bypass",
                test_description="Payment status manipulation"
            )
            
            if result:
                self.results.append(result)
    
    def _test_quantity_manipulation(self, url: str):
        """
        Test for quantity manipulation vulnerabilities
        """
        print(f"  [→] Testing quantity manipulation...")
        
        quantity_tests = [
            {'price': 100, 'quantity': -1},      # Negative quantity
            {'amount': 100, 'quantity': 0},      # Zero quantity
            {'price': 100, 'quantity': 0.01},    # Fractional quantity
            {'amount': 100, 'quantity': 999999}, # Huge quantity
            {'price': 100, 'quantity': ''},      # Empty quantity
        ]
        
        for payload in quantity_tests:
            result = self._send_payment_request(
                url=url,
                payload=payload,
                test_type="Quantity Manipulation",
                test_description=f"Quantity: {payload.get('quantity')}"
            )
            
            if result:
                self.results.append(result)
    
    def _send_payment_request(
        self,
        url: str,
        payload: Dict,
        test_type: str,
        test_description: str
    ) -> Dict:
        """
        Send payment request and analyze response
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
            is_vulnerable = self._analyze_payment_response(
                response=response,
                payload=payload,
                test_type=test_type
            )
            
            if is_vulnerable:
                return {
                    'vulnerability': f'Payment Logic Flaw - {test_type}',
                    'severity': self._get_severity(test_type),
                    'confidence': is_vulnerable['confidence'],
                    'url': url,
                    'method': 'POST',
                    'payload': json.dumps(payload, indent=2, default=str),
                    'test_description': test_description,
                    'evidence': is_vulnerable['evidence'],
                    'response_code': response.status_code,
                    'response_snippet': response.text[:300],
                    'impact': self._get_impact(test_type),
                    'remediation': self._get_remediation(),
                    'cvss_score': self._get_cvss(test_type),
                    'cwe': 'CWE-840'
                }
            
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def _analyze_payment_response(
        self,
        response: requests.Response,
        payload: Dict,
        test_type: str
    ) -> Dict:
        """
        Analyze payment response for vulnerabilities
        """
        evidence = []
        confidence = 0
        
        # Check 1: Success status code
        if 200 <= response.status_code < 300:
            confidence += 40
            evidence.append(f"Payment accepted with status {response.status_code}")
        
        try:
            response_text = response.text.lower()
            
            # Check 2: Success indicators
            success_keywords = [
                'success', 'completed', 'confirmed', 'approved',
                'payment successful', 'order placed', 'transaction complete',
                'thank you', 'receipt', 'invoice', '"status":"success"',
                '"payment_status":"completed"', '"paid":true'
            ]
            
            if any(keyword in response_text for keyword in success_keywords):
                confidence += 30
                evidence.append("Payment success indicators found")
            
            # Check 3: Order/transaction ID in response
            order_patterns = [
                r'order[_\s]?id["\s:]+\d+',
                r'transaction[_\s]?id["\s:]+[a-zA-Z0-9]+',
                r'reference[_\s]?number',
            ]
            
            if any(re.search(pattern, response_text) for pattern in order_patterns):
                confidence += 20
                evidence.append("Order/Transaction ID generated")
            
            # Check 4: Check for zero amount acceptance
            if 'amount' in payload and payload['amount'] in [0, '0', 0.00]:
                confidence += 10
                evidence.append("Zero amount accepted")
            
            # Check 5: JSON response analysis
            try:
                json_resp = response.json()
                
                # Check if payment was processed
                payment_indicators = ['order_id', 'transaction_id', 'payment_id', 'invoice_id']
                if any(key in json_resp for key in payment_indicators):
                    confidence += 15
                    evidence.append("Payment processed successfully")
                
            except:
                pass
            
        except:
            pass
        
        # Vulnerability confirmed if confidence >= 60
        if confidence >= 60:
            return {
                'confidence': min(confidence, 95),
                'evidence': evidence
            }
        
        return None
    
    def _get_severity(self, test_type: str) -> str:
        """
        Get severity based on test type
        """
        critical_types = ['Payment Bypass', 'Price Manipulation']
        high_types = ['Negative Amount Acceptance', 'Currency Manipulation', 'Discount Abuse']
        
        if test_type in critical_types:
            return 'CRITICAL'
        elif test_type in high_types:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_cvss(self, test_type: str) -> float:
        """
        Get CVSS score
        """
        scores = {
            'Payment Bypass': 9.3,
            'Price Manipulation': 9.1,
            'Negative Amount Acceptance': 8.5,
            'Currency Manipulation': 8.2,
            'Discount Abuse': 7.8,
            'Tax Evasion': 7.0,
            'Rounding Error Exploitation': 6.5,
            'Quantity Manipulation': 7.5
        }
        return scores.get(test_type, 7.0)
    
    def _get_impact(self, test_type: str) -> str:
        """
        Get impact description
        """
        impacts = {
            'Payment Bypass': 'Attacker can bypass payment completely and get products/services for free',
            'Price Manipulation': 'Attacker can set arbitrary prices causing severe financial loss',
            'Negative Amount Acceptance': 'Attacker can exploit refund system to steal money',
            'Currency Manipulation': 'Attacker can pay in cheaper currencies than intended',
            'Discount Abuse': 'Attacker can apply excessive discounts causing financial loss',
            'Tax Evasion': 'Attacker can avoid paying taxes',
            'Rounding Error Exploitation': 'Attacker can exploit rounding to get free items',
            'Quantity Manipulation': 'Attacker can manipulate quantities in unexpected ways'
        }
        return impacts.get(test_type, 'Financial loss due to payment logic flaw')
    
    def _get_remediation(self) -> str:
        """
        Get remediation advice
        """
        return """
        1. NEVER trust client-side price/amount calculations
        2. Always recalculate prices server-side from product database
        3. Validate all payment amounts are positive and non-zero
        4. Implement server-side validation for:
           - Price integrity
           - Currency validity
           - Discount limits
           - Tax calculations
           - Quantity limits
        5. Use decimal types for financial calculations (never float)
        6. Implement transaction logging and monitoring
        7. Add alerts for suspicious transactions
        8. Use secure payment gateways (Stripe, PayPal, etc.)
        
        Example (Python):
        ```python
        # ❌ Vulnerable code
        amount = request.POST.get('amount')
        process_payment(amount)
        
        # ✅ Secure code
        product_id = request.POST.get('product_id')
        quantity = int(request.POST.get('quantity', 1))
        
        # Server-side price lookup
        product = Product.objects.get(id=product_id)
        
        # Server-side calculation
        subtotal = Decimal(product.price) * Decimal(quantity)
        tax = subtotal * Decimal('0.1')  # 10% tax
        total = subtotal + tax
        
        # Validate
        if total <= 0:
            raise ValueError("Invalid amount")
        
        process_payment(total)
        ```
        """


# Example usage
if __name__ == "__main__":
    scanner = PaymentLogicScanner("https://example.com")
    results = scanner.scan()
    
    print(f"\n[+] Found {len(results)} payment logic vulnerabilities")
    for vuln in results:
        print(f"\n🔴 {vuln['vulnerability']}")
        print(f"   URL: {vuln['url']}")
        print(f"   Confidence: {vuln['confidence']}%")
        print(f"   Impact: {vuln['impact']}")
