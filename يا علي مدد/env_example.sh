# ============================================================================
# AlBaTTaR BUGS - Environment Variables Configuration
# ============================================================================
# Copy this file to .env and fill in your actual values
# Never commit the .env file to version control!
# ============================================================================

# ----------------------------------------------------------------------------
# AI API KEYS (Optional - for AI-powered analysis)
# ----------------------------------------------------------------------------

# OpenAI GPT-4 API Key
# Get your key from: https://platform.openai.com/api-keys
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Anthropic Claude API Key
# Get your key from: https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Local AI Model Settings (if using local models)
LOCAL_MODEL_PATH=models/llama3-8b.gguf
LOCAL_MODEL_TYPE=llama


# ----------------------------------------------------------------------------
# NOTIFICATION SERVICES (Optional)
# ----------------------------------------------------------------------------

# Slack Integration
# Create webhook at: https://api.slack.com/messaging/webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
SLACK_CHANNEL=#security-alerts

# Discord Integration
# Create webhook in Server Settings > Integrations > Webhooks
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

# Telegram Bot
# Create bot via @BotFather on Telegram
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=1234567890

# Email Notifications (SMTP)
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=recipient@example.com
EMAIL_PASSWORD=your-app-specific-password
EMAIL_USE_TLS=true


# ----------------------------------------------------------------------------
# BUG BOUNTY PLATFORMS (Optional)
# ----------------------------------------------------------------------------

# HackerOne API
# Get credentials from: https://hackerone.com/settings/api_tokens
HACKERONE_API_KEY=your_hackerone_api_key
HACKERONE_USERNAME=your_username

# Bugcrowd API
# Get from: https://bugcrowd.com/user/settings/api
BUGCROWD_API_KEY=your_bugcrowd_api_key


# ----------------------------------------------------------------------------
# EXTERNAL APIs (Optional - for reconnaissance)
# ----------------------------------------------------------------------------

# Shodan API
# Get from: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key

# SecurityTrails API
# Get from: https://securitytrails.com/app/account/credentials
SECURITYTRAILS_API_KEY=your_securitytrails_api_key

# VirusTotal API
# Get from: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# BuiltWith API
# Get from: https://api.builtwith.com/
BUILTWITH_API_KEY=your_builtwith_api_key


# ----------------------------------------------------------------------------
# PROXY SETTINGS (Optional)
# ----------------------------------------------------------------------------

# HTTP/HTTPS Proxy
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=https://proxy.example.com:8080

# SOCKS5 Proxy
SOCKS_PROXY=socks5://127.0.0.1:9050

# Proxy Authentication (if required)
PROXY_USERNAME=your_proxy_username
PROXY_PASSWORD=your_proxy_password


# ----------------------------------------------------------------------------
# DATABASE SETTINGS (Optional - defaults to SQLite)
# ----------------------------------------------------------------------------

# Database Type (sqlite, postgresql, mysql)
DB_TYPE=sqlite

# SQLite (default)
DB_PATH=data/scans.db

# PostgreSQL (if using)
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=albattar_bugs
# DB_USER=postgres
# DB_PASSWORD=your_password

# MySQL (if using)
# DB_HOST=localhost
# DB_PORT=3306
# DB_NAME=albattar_bugs
# DB_USER=root
# DB_PASSWORD=your_password


# ----------------------------------------------------------------------------
# CALLBACK SERVERS (Optional - for blind vulnerabilities)
# ----------------------------------------------------------------------------

# Blind XSS Callback Server
XSS_CALLBACK_SERVER=https://your-xss-callback.com

# XXE Out-of-Band Server
XXE_OOB_SERVER=http://your-xxe-server.com

# SSRF Callback Server
SSRF_CALLBACK_SERVER=http://your-ssrf-callback.com


# ----------------------------------------------------------------------------
# CUSTOM SETTINGS
# ----------------------------------------------------------------------------

# Default User Agent
USER_AGENT=AlBaTTaR-BUGS/1.0 (Security Scanner)

# Maximum Threads
MAX_THREADS=50

# Request Timeout (seconds)
REQUEST_TIMEOUT=30

# Rate Limit (requests per second)
RATE_LIMIT=10

# Scan Results Retention (days)
RESULTS_RETENTION_DAYS=365


# ----------------------------------------------------------------------------
# DEBUG & DEVELOPMENT
# ----------------------------------------------------------------------------

# Debug Mode (true/false)
DEBUG=false

# Verbose Logging (true/false)
VERBOSE=false

# Log Level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=INFO

# Save HTTP Requests/Responses (true/false)
LOG_HTTP_TRAFFIC=false


# ----------------------------------------------------------------------------
# SECURITY SETTINGS
# ----------------------------------------------------------------------------

# Ethical Mode (prevents destructive tests)
ETHICAL_MODE=true

# Respect robots.txt
RESPECT_ROBOTS_TXT=true

# Stealth Mode (slower but more careful)
STEALTH_MODE=false

# Maximum Scan Duration (seconds, 0 = unlimited)
MAX_SCAN_DURATION=3600

# Auto-stop on Ban Detection (true/false)
AUTO_STOP_ON_BAN=true


# ----------------------------------------------------------------------------
# SCOPE MANAGEMENT
# ----------------------------------------------------------------------------

# Scope File Path
SCOPE_FILE=scope.txt

# Strict Scope Mode (true/false)
STRICT_SCOPE=true

# Allow Subdomains (true/false)
ALLOW_SUBDOMAINS=true


# ----------------------------------------------------------------------------
# REPORT SETTINGS
# ----------------------------------------------------------------------------

# Default Report Format (json, html, pdf, markdown, csv, xml)
REPORT_FORMAT=html,json

# Output Directory
OUTPUT_DIR=reports/

# Include Screenshots in Reports (true/false)
INCLUDE_SCREENSHOTS=true

# Include Proof-of-Concept (true/false)
INCLUDE_POC=true

# Include Remediation Steps (true/false)
INCLUDE_REMEDIATION=true


# ----------------------------------------------------------------------------
# PERFORMANCE TUNING
# ----------------------------------------------------------------------------

# Enable Caching (true/false)
CACHE_ENABLED=true

# Cache Size (MB)
CACHE_SIZE=100

# Memory Limit (GB)
MEMORY_LIMIT=2

# CPU Limit (percentage)
CPU_LIMIT=80


# ----------------------------------------------------------------------------
# ADVANCED AI SETTINGS
# ----------------------------------------------------------------------------

# AI Temperature (0.0 - 2.0, lower = more focused)
AI_TEMPERATURE=0.3

# AI Max Tokens
AI_MAX_TOKENS=4096

# Enable AI False Positive Filtering (true/false)
AI_FILTER_FALSE_POSITIVES=true

# Enable AI Payload Generation (true/false)
AI_GENERATE_PAYLOADS=true

# Enable AI Learning (true/false)
AI_LEARNING_ENABLED=true

# AI Cache TTL (seconds)
AI_CACHE_TTL=86400


# ----------------------------------------------------------------------------
# NOTES
# ----------------------------------------------------------------------------
# - Remove the '#' at the beginning of a line to enable that setting
# - Keep sensitive information secure and never share your .env file
# - Refer to the documentation for detailed configuration options
# - For support, visit: https://docs.albattar-bugs.com
# ============================================================================