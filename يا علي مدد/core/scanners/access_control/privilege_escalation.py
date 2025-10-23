"""
Privilege Escalation Scanner
كشف ثغرات رفع الصلاحيات (Horizontal/Vertical)
"""

import requests
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode


class PrivilegeEscalationScanner:
    """ماسح ثغرات رفع الصلاحيات"""
    
    def __init__(self, target: str, config: dict = None):
        self.target = target
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        
        # Parameters للصلاحيات
        self.privilege_params = [
            'role', 'user_role', 'user_type', 'type',
            'admin', 'is_admin', 'isAdmin', 'administrator',
            'privilege', 'permission', 'access_level', 'level',
            'group', 'user_group', 'account_type', 'status'
        ]
        
        # قيم الصلاحيات العالية
        self.high_privilege_values = [
            'admin', 'administrator', 'root', 'superuser',
            'super_admin', 'superadmin', 'sysadmin',
            'moderator', 'manager', 'owner', 'master',
            '1', 'true', 'True', 'yes', 'Yes'
        ]
        
    def scan(self) -> List[Dict]:
        """تنفيذ الفحص الكامل"""
        print(f"🔍 Starting Privilege Escalation scan on: {self.target}")
        
        # 1. Horizontal Privilege Escalation
        self._test_horizontal_escalation()
        
        # 2. Vertical Privilege Escalation
        self._test_vertical_escalation()
        
        # 3. Parameter Manipulation
        self._test_parameter_manipulation()
        
        # 4. HTTP Method Override
        self._test_method_override()
        
        # 5. Mass Assignment
        self._test_mass_assignment()
        
        # 6. Function Level Access Control
        self._test_function_access()
        
        # 7. API Privilege Escalation
        self._test_api_escalation()
        
        print(f"✅ Found {len(self.vulnerabilities)} privilege escalation vulnerabilities")
        return self.vulnerabilities
    
    def _test_horizontal_escalation(self):
        """اختبار رفع الصلاحيات الأفقي"""
        print("  📡 Testing horizontal privilege escalation...")
        
        try:
            # محاولة الوصول لموارد مستخدمين آخرين
            user_endpoints = [
                '/profile', '/account', '/settings', '/dashboard',
                '/user/profile', '/api/user', '/api/account',
                '/my-account', '/my-profile'
            ]
            
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint in user_endpoints:
                test_url = base_url + endpoint
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    # فحص إذا كان يحتوي معلومات مستخدم
                    if response.status_code == 200:
                        if self._contains_user_data(response.text):
                            # محاولة تعديل user_id
                            if self._test_user_id_manipulation(test_url):
                                print(f"    ✅ Horizontal escalation found: {endpoint}")
                                
                except Exception:
                    continue
                    
        except Exception as e:
            pass
    
    def _test_vertical_escalation(self):
        """اختبار رفع الصلاحيات العمودي"""
        print("  📡 Testing vertical privilege escalation...")
        
        try:
            # محاولة الوصول لصفحات admin
            admin_endpoints = [
                '/admin', '/admin/', '/administrator',
                '/admin/dashboard', '/admin/panel',
                '/admin/users', '/admin/settings',
                '/wp-admin', '/cpanel', '/control-panel',
                '/manage', '/management', '/backend'
            ]
            
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for endpoint in admin_endpoints:
                test_url = base_url + endpoint
                
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    
                    # إذا كان accessible
                    if response.status_code in [200, 301, 302]:
                        # فحص إذا كانت صفحة admin حقيقية
                        if self._is_admin_page(response):
                            self.vulnerabilities.append({
                                'type': 'Privilege Escalation',
                                'subtype': 'Vertical - Admin Access',
                                'severity': 'critical',
                                'url': test_url,
                                'confidence': 85,
                                'evidence': {
                                    'status_code': response.status_code,
                                    'accessible': True
                                },
                                'description': 'Admin panel accessible without proper authentication',
                                'remediation': 'Implement proper role-based access control'
                            })
                            print(f"    🔴 Admin panel accessible: {endpoint}")
                            
                except Exception:
                    continue
                    
        except Exception as e:
            pass
    
    def _test_parameter_manipulation(self):
        """اختبار التلاعب بمعاملات الصلاحيات"""
        print("  📡 Testing privilege parameter manipulation...")
        
        try:
            for param in self.privilege_params:
                for value in self.high_privilege_values:
                    
                    # GET request
                    params = {param: value}
                    response = self.session.get(
                        self.target,
                        params=params,
                        timeout=10
                    )
                    
                    if self._check_elevated_access(response):
                        self.vulnerabilities.append({
                            'type': 'Privilege Escalation',
                            'subtype': 'Parameter Manipulation',
                            'severity': 'critical',
                            'url': self.target,
                            'parameter': param,
                            'value': value,
                            'method': 'GET',
                            'confidence': 80,
                            'description': f'Privilege escalation via parameter: {param}={value}',
                            'remediation': 'Never trust client-side privilege parameters'
                        })
                        print(f"    ✅ Parameter escalation: {param}={value}")
                        return
                    
                    # POST request
                    data = {param: value}
                    response = self.session.post(
                        self.target,
                        data=data,
                        timeout=10
                    )
                    
                    if self._check_elevated_access(response):
                        self.vulnerabilities.append({
                            'type': 'Privilege Escalation',
                            'subtype': 'Parameter Manipulation',
                            'severity': 'critical',
                            'url': self.target,
                            'parameter': param,
                            'value': value,
                            'method': 'POST',
                            'confidence': 80,
                            'description': f'Privilege escalation via POST data: {param}={value}',
                            'remediation': 'Validate privileges server-side'
                        })
                        print(f"    ✅ POST escalation: {param}={value}")
                        return
                        
        except Exception as e:
            pass
    
    def _test_method_override(self):
        """اختبار HTTP Method Override"""
        print("  📡 Testing HTTP method override escalation...")
        
        try:
            # Headers للـ method override
            override_headers = [
                {'X-HTTP-Method-Override': 'PUT'},
                {'X-HTTP-Method-Override': 'DELETE'},
                {'X-HTTP-Method-Override': 'PATCH'},
                {'X-Method-Override': 'PUT'},
                {'X-Method-Override': 'DELETE'},
            ]
            
            for headers in override_headers:
                response = self.session.post(
                    self.target,
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code in [200, 201, 204]:
                    self.vulnerabilities.append({
                        'type': 'Privilege Escalation',
                        'subtype': 'HTTP Method Override',
                        'severity': 'high',
                        'url': self.target,
                        'headers': headers,
                        'confidence': 75,
                        'description': 'Privilege escalation via HTTP method override',
                        'remediation': 'Disable method override headers or validate properly'
                    })
                    print(f"    ✅ Method override escalation: {headers}")
                    break
                    
        except Exception as e:
            pass
    
    def _test_mass_assignment(self):
        """اختبار Mass Assignment"""
        print("  📡 Testing mass assignment escalation...")
        
        try:
            # محاولة إضافة حقول صلاحيات
            mass_assignment_fields = {
                'role': 'admin',
                'is_admin': True,
                'admin': 1,
                'privilege': 'administrator',
                'access_level': 'admin',
                'user_type': 'admin',
                'account_type': 'admin'
            }
            
            # POST request
            response = self.session.post(
                self.target,
                data=mass_assignment_fields,
                timeout=10
            )
            
            if self._check_elevated_access(response):
                self.vulnerabilities.append({
                    'type': 'Privilege Escalation',
                    'subtype': 'Mass Assignment',
                    'severity': 'critical',
                    'url': self.target,
                    'fields': list(mass_assignment_fields.keys()),
                    'confidence': 85,
                    'description': 'Mass assignment allows privilege escalation',
                    'remediation': 'Whitelist allowed fields, never mass-assign privilege fields'
                })
                print(f"    🔴 Mass assignment escalation found!")
            
            # JSON request
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(
                self.target,
                data=json.dumps(mass_assignment_fields),
                headers=headers,
                timeout=10
            )
            
            if self._check_elevated_access(response):
                self.vulnerabilities.append({
                    'type': 'Privilege Escalation',
                    'subtype': 'Mass Assignment (JSON)',
                    'severity': 'critical',
                    'url': self.target,
                    'fields': list(mass_assignment_fields.keys()),
                    'confidence': 85,
                    'description': 'JSON mass assignment allows privilege escalation',
                    'remediation': 'Whitelist allowed fields in JSON requests'
                })
                print(f"    🔴 JSON mass assignment escalation!")
                
        except Exception as e:
            pass
    
    def _test_function_access(self):
        """اختبار Function Level Access Control"""
        print("  📡 Testing function level access control...")
        
        try:
            # وظائف إدارية شائعة
            admin_functions = [
                '/api/admin/users',
                '/api/admin/delete',
                '/api/users/delete',
                '/api/users/promote',
                '/api/settings/update',
                '/api/config/update',
                '/admin/api/users',
                '/admin/api/settings'
            ]
            
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for function in admin_functions:
                test_url = base_url + function
                
                try:
                    # GET request
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        if self._contains_sensitive_data(response.text):
                            self.vulnerabilities.append({
                                'type': 'Privilege Escalation',
                                'subtype': 'Function Level Access Control',
                                'severity': 'high',
                                'url': test_url,
                                'confidence': 80,
                                'description': 'Admin function accessible without proper authorization',
                                'remediation': 'Implement function-level access control checks'
                            })
                            print(f"    ✅ Function access vulnerability: {function}")
                            
                except Exception:
                    continue
                    
        except Exception as e:
            pass
    
    def _test_api_escalation(self):
        """اختبار API Privilege Escalation"""
        print("  📡 Testing API privilege escalation...")
        
        try:
            # محاولة تعديل بيانات مستخدم آخر
            api_methods = ['PUT', 'PATCH', 'DELETE']
            
            for method in api_methods:
                try:
                    response = self.session.request(
                        method,
                        self.target,
                        timeout=10
                    )
                    
                    if response.status_code in [200, 201, 204]:
                        self.vulnerabilities.append({
                            'type': 'Privilege Escalation',
                            'subtype': 'API Method Escalation',
                            'severity': 'high',
                            'url': self.target,
                            'method': method,
                            'confidence': 75,
                            'description': f'{method} method allowed without proper authorization',
                            'remediation': 'Validate user permissions for each HTTP method'
                        })
                        print(f"    ⚠️  API {method} escalation possible")
                        
                except Exception:
                    continue
            
            # محاولة تعديل user_id في JSON
            if '/api/' in self.target:
                test_data = {
                    'user_id': 1,
                    'id': 1,
                    'admin': True,
                    'role': 'admin'
                }
                
                headers = {'Content-Type': 'application/json'}
                
                for method in ['PUT', 'PATCH']:
                    try:
                        response = self.session.request(
                            method,
                            self.target,
                            data=json.dumps(test_data),
                            headers=headers,
                            timeout=10
                        )
                        
                        if response.status_code in [200, 201]:
                            self.vulnerabilities.append({
                                'type': 'Privilege Escalation',
                                'subtype': 'API Data Manipulation',
                                'severity': 'critical',
                                'url': self.target,
                                'method': method,
                                'confidence': 70,
                                'description': 'API allows manipulation of user privileges',
                                'remediation': 'Validate authorization before updating user data'
                            })
                            print(f"    🔴 API data manipulation: {method}")
                            break
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
    
    def _test_user_id_manipulation(self, url: str) -> bool:
        """اختبار التلاعب بـ user_id"""
        try:
            # الطلب الأصلي
            response1 = self.session.get(url, timeout=10)
            
            if response1.status_code != 200:
                return False
            
            # محاولة تغيير user_id
            test_params = [
                {'user_id': '1'},
                {'user_id': '2'},
                {'id': '1'},
                {'id': '2'},
                {'uid': '1'},
            ]
            
            for params in test_params:
                response2 = self.session.get(url, params=params, timeout=10)
                
                if response2.status_code == 200:
                    # فحص إذا كان المحتوى مختلف
                    if response1.text != response2.text:
                        if self._contains_user_data(response2.text):
                            self.vulnerabilities.append({
                                'type': 'Privilege Escalation',
                                'subtype': 'Horizontal - User ID Manipulation',
                                'severity': 'high',
                                'url': url,
                                'parameters': params,
                                'confidence': 85,
                                'description': 'Can access other users data by manipulating user_id',
                                'remediation': 'Verify user identity before returning data'
                            })
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _check_elevated_access(self, response) -> bool:
        """فحص إذا تم الحصول على صلاحيات عالية"""
        if response.status_code not in [200, 201]:
            return False
        
        text_lower = response.text.lower()
        
        # مؤشرات الوصول المرتفع
        elevated_indicators = [
            'admin panel', 'admin dashboard', 'administrator',
            'welcome admin', 'admin area', 'control panel',
            'user management', 'system settings', 'manage users',
            '"role":"admin"', '"role": "admin"',
            '"is_admin":true', '"is_admin": true',
            '"admin":true', '"admin": true'
        ]
        
        if any(indicator in text_lower for indicator in elevated_indicators):
            # التأكد من عدم وجود رسائل خطأ
            error_indicators = ['error', 'unauthorized', 'forbidden', 'denied']
            
            if not any(error in text_lower for error in error_indicators):
                return True
        
        return False
    
    def _is_admin_page(self, response) -> bool:
        """فحص إذا كانت صفحة admin"""
        if response.status_code not in [200, 301, 302]:
            return False
        
        text_lower = response.text.lower()
        
        admin_indicators = [
            '<title>admin', 'admin panel', 'dashboard',
            'administration', 'control panel', 'cpanel',
            'manage users', 'user management', 'settings'
        ]
        
        return any(indicator in text_lower for indicator in admin_indicators)
    
    def _contains_user_data(self, text: str) -> bool:
        """فحص إذا كان يحتوي بيانات مستخدم"""
        user_indicators = [
            'email', 'username', 'user_name', 'phone',
            'address', 'profile', 'account', 'password'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in user_indicators)
    
    def _contains_sensitive_data(self, text: str) -> bool:
        """فحص إذا كان يحتوي بيانات حساسة"""
        sensitive_indicators = [
            'password', 'secret', 'api_key', 'token',
            'credit_card', 'ssn', 'salary', 'confidential'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in sensitive_indicators)
    
    def generate_report(self) -> dict:
        """توليد تقرير شامل"""
        return {
            'scanner': 'Privilege Escalation Scanner',
            'target': self.target,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'low']),
            }
        }


if __name__ == "__main__":
    target = "http://example.com/api/user/profile"
    scanner = PrivilegeEscalationScanner(target)
    results = scanner.scan()
    
    print("\n" + "="*60)
    print("📊 PRIVILEGE ESCALATION SCAN RESULTS")
    print("="*60)
    report = scanner.generate_report()
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Critical: {report['summary']['critical']}")
    print(f"High: {report['summary']['high']}")
