# ⚔️ AlBaTTaR BUGS - AI-Powered Bug Bounty Hunter

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Professional Vulnerability Scanner with Advanced AI Analysis**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🎯 Overview

**AlBaTTaR BUGS** is a cutting-edge, AI-powered vulnerability scanner designed for bug bounty hunters, penetration testers, and security researchers. With support for 120+ vulnerability types and advanced artificial intelligence for false positive filtering, it's your ultimate companion for discovering security flaws.

### 🌟 Why AlBaTTaR BUGS?

- 🤖 **AI-Powered Analysis**: Advanced GPT-4 and Claude integration for intelligent vulnerability detection
- 🎯 **120+ Vulnerabilities**: Comprehensive coverage of injection, XSS, XXE, SSRF, and more
- 🛡️ **WAF Bypass**: Sophisticated techniques to bypass Cloudflare, ModSecurity, and other WAFs
- 📊 **Professional Reports**: Beautiful HTML/PDF reports with detailed remediation steps
- ⚡ **High Performance**: Multi-threaded scanning with intelligent rate limiting
- 🔍 **Smart Reconnaissance**: Subdomain enumeration, tech stack detection, and more
- 🎨 **User-Friendly**: Clean CLI interface with real-time progress indicators

---

## ✨ Features

### 🔥 Core Capabilities

- **Injection Attacks** (40+ types)
  - SQL Injection (Union, Boolean, Time-based, Error-based)
  - NoSQL Injection (MongoDB, Redis, CouchDB)
  - Command Injection (OS Command, Blind)
  - Code Injection (PHP, Python, Ruby, Node.js)
  - Template Injection (SSTI - Jinja2, Twig, Smarty)
  - LDAP, XPath, XML Injection

- **Cross-Site Scripting** (15+ types)
  - Reflected, Stored, DOM-based XSS
  - Blind XSS with callback server
  - Mutation XSS (mXSS)
  - WAF bypass techniques

- **File Inclusion & Traversal**
  - Local File Inclusion (LFI)
  - Remote File Inclusion (RFI)
  - Path Traversal
  - PHP Wrapper attacks
  - Log Poisoning

- **XXE & SSRF**
  - XML External Entity attacks
  - Server-Side Request Forgery
  - Cloud metadata exploitation (AWS, Azure, GCP)
  - Blind SSRF detection

- **Authentication & Access Control**
  - Authentication bypass
  - JWT vulnerabilities
  - Session fixation/hijacking
  - IDOR detection
  - Privilege escalation
  - CORS misconfiguration

- **Business Logic & API**
  - Race conditions
  - Mass assignment
  - Payment logic flaws
  - GraphQL vulnerabilities
  - REST API issues

### 🤖 AI Features

- **False Positive Filtering**: AI eliminates 95%+ of false positives
- **Context Analysis**: Understanding application logic
- **Smart Payload Generation**: AI creates custom payloads
- **Vulnerability Classification**: Automatic severity rating
- **Exploit Suggestions**: Detailed exploitation steps
- **Learning Module**: Improves from previous scans

### 🛡️ WAF Bypass

- Automatic WAF detection (Cloudflare, ModSecurity, Imperva, etc.)
- Multiple encoding techniques
- Payload obfuscation
- Timing strategies
- IP rotation support

---

## 📦 Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Git

### Quick Install

```bash
# Clone the repository
git clone https://github.com/albattar-bugs/albattar-bugs.git
cd albattar-bugs

# Install dependencies
pip install -r requirements.txt

# Or install using setup.py
python setup.py install

# Run the tool
python main.py --help
```

### Docker Installation (Alternative)

```bash
docker pull albattar/albattar-bugs:latest
docker run -it albattar/albattar-bugs -u https://example.com
```

### Configuration

1. Copy the environment template:
```bash
cp .env.example .env
```

2. Edit `.env` and add your API keys:
```bash
# AI API Keys (Optional)
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_claude_key_here

# Notification Services (Optional)
SLACK_WEBHOOK_URL=your_slack_webhook
DISCORD_WEBHOOK_URL=your_discord_webhook
TELEGRAM_BOT_TOKEN=your_telegram_token
TELEGRAM_CHAT_ID=your_chat_id
```

---

## 🚀 Usage

### Basic Examples

```bash
# Quick scan
python main.py -u https://example.com

# Full scan with AI
python main.py -u https://example.com --scan-type full --ai

# Scan specific vulnerabilities
python main.py -u https://example.com --vulns sqli xss lfi

# Scan with custom threads
python main.py -u https://example.com --threads 50 --timeout 60
```

### Advanced Examples

```bash
# Stealth scan with proxy
python main.py -u https://example.com \
    --stealth \
    --proxy socks5://127.0.0.1:9050 \
    --random-agent

# Scan multiple targets
python main.py --list targets.txt --ai --threads 20

# API testing
python main.py -u https://api.example.com \
    --api-mode \
    --bearer-token "your_token" \
    --vulns idor jwt api_abuse

# Generate PDF report
python main.py -u https://example.com \
    --report-format pdf html \
    --output reports/example_scan.pdf

# Bug bounty mode
python main.py -u https://example.com \
    --ai \
    --detect-waf \
    --waf-bypass \
    --slack-webhook "your_webhook"
```

### Command Line Options

```
Target Options:
  -u, --url              Target URL to scan
  -l, --list             File containing list of targets

Scan Options:
  --scan-type            Scan intensity (quick/normal/full/deep)
  --vulns                Specific vulnerabilities to scan
  --ai                   Enable AI-powered analysis
  --threads              Number of threads (default: 10)

Network Options:
  --proxy                Proxy URL
  --random-agent         Use random User-Agent
  --headers              Custom headers file
  --cookies              Cookie string

Output Options:
  -o, --output           Output file/directory
  --report-format        Report format (json/html/pdf/markdown)
  --no-report            Disable report generation

Advanced Options:
  --stealth              Enable stealth mode
  --detect-waf           Detect WAF
  --waf-bypass           Attempt WAF bypass
  --recon                Run reconnaissance modules
  -v, --verbose          Verbose output
  --debug                Debug mode
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS v1.0 - AI-Powered Scanner  ⚔️     ║
║              Created by ROBIN | @ll bUg                     ║
╚══════════════════════════════════════════════════════════════╝

[12:00:00] 🎯 Target: https://example.com
[12:00:01] ✅ Target is valid and reachable
[12:00:02] 🔍 Fingerprinting: PHP 8.1, Apache 2.4, MySQL 8.0
[12:00:03] 🛡️  WAF Detected: Cloudflare
[12:00:04] 🚀 Starting scan with 50 threads...

[12:00:30] 🤖 AI is analyzing 127 potential findings...
[12:00:45] ✅ AI Analysis complete!

╔══════════════════════════════════════════════════════════════╗
║                   VULNERABILITIES FOUND                      ║
╚══════════════════════════════════════════════════════════════╝

🔴 CRITICAL (3)
  ├─ SQL Injection @ /user.php?id=1
  │  Confidence: 98% | CVSS: 9.8
  ├─ Remote Code Execution @ /upload.php
  │  Confidence: 95% | CVSS: 10.0
  └─ Authentication Bypass @ /admin/login
     Confidence: 92% | CVSS: 9.1

🟠 HIGH (5)
🟡 MEDIUM (7)
🟢 LOW (4)

📊 TOTAL: 19 vulnerabilities

⏱️  Duration: 3 minutes 42 seconds
📨 Total Requests: 1,247
🧠 AI Tokens Used: 45,230

📝 Report saved: reports/example_com_2025-10-22.pdf
```

---

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [User Manual](docs/usage.md)
- [Advanced Usage](docs/advanced.md)
- [API Reference](docs/api_reference.md)
- [Contributing Guide](docs/contributing.md)
- [FAQ](docs/faq.md)

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository

---

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is for **ETHICAL** use only.

✅ **Legal Uses:**
- Bug bounty programs
- Authorized penetration testing
- Testing your own applications
- Security research with permission

❌ **Illegal Uses:**
- Unauthorized testing
- Accessing systems without permission
- Data theft
- Any criminal activity

**The developers are NOT responsible for misuse of this tool.**

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**ROBIN (@ll bUg)**
- GitHub: [@albattar-bugs](https://github.com/albattar-bugs)
- Twitter: [@albattar_bugs](https://twitter.com/albattar_bugs)
- Email: contact@albattar-bugs.com

---

## 🙏 Acknowledgments

- OWASP for security resources
- Bug bounty community
- All contributors and supporters

---

## 📞 Support

- 💬 Discord: [Join our server](https://discord.gg/albattar-bugs)
- 🐛 Issues: [GitHub Issues](https://github.com/albattar-bugs/issues)
- 📧 Email: support@albattar-bugs.com
- 📚 Docs: [Documentation](https://docs.albattar-bugs.com)

---

<div align="center">

**Made with ❤️ by ROBIN**

If you find this tool useful, please ⭐ star the repository!

</div>
