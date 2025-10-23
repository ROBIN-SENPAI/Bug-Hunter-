#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         ⚔️  ALBATTAR BUGS - AI-Powered Security Scanner  ⚔️ ║
║              Created by ROBIN | @ll bUg                     ║
║              Version 1.0.0 | 2025                           ║
╚══════════════════════════════════════════════════════════════╝

AlBaTTaR BUGS - Advanced Bug Bounty Hunting Tool
Professional vulnerability scanner with AI-powered analysis
"""

import sys
import os
import argparse
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.banner import display_banner
from utils.logger import setup_logger, log_info, log_error, log_success, log_warning
from utils.colors import Colors
from core.target_validator import TargetValidator
from core.scan_orchestrator import ScanOrchestrator

__version__ = "1.0.0"
__author__ = "ROBIN (@ll bUg)"
__license__ = "MIT"


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AlBaTTaR BUGS - AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan
  python main.py -u https://example.com
  
  # Full scan with AI
  python main.py -u https://example.com --scan-type full --ai
  
  # Scan specific vulnerabilities
  python main.py -u https://example.com --vulns sqli xss lfi
  
  # Advanced scan with custom settings
  python main.py -u https://example.com --threads 50 --timeout 60 --proxy http://127.0.0.1:8080
  
  # Scan multiple targets
  python main.py --list targets.txt --ai --output results/
  
For more information, visit: https://github.com/albattar-bugs
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', 
                             help='Target URL to scan')
    target_group.add_argument('-l', '--list', 
                             help='File containing list of targets')
    
    # Scan options
    parser.add_argument('--scan-type', 
                       choices=['quick', 'normal', 'full', 'deep'],
                       default='normal',
                       help='Scan intensity level (default: normal)')
    
    parser.add_argument('--vulns', 
                       nargs='+',
                       help='Specific vulnerabilities to scan (sqli, xss, lfi, etc)')
    
    parser.add_argument('--exclude-vulns',
                       nargs='+',
                       help='Vulnerabilities to exclude from scan')
    
    # AI options
    parser.add_argument('--ai',
                       action='store_true',
                       help='Enable AI-powered analysis')
    
    parser.add_argument('--ai-model',
                       choices=['gpt-4', 'claude', 'local', 'auto'],
                       default='auto',
                       help='AI model to use (default: auto)')
    
    # Performance options
    parser.add_argument('-t', '--threads',
                       type=int,
                       default=10,
                       help='Number of threads (default: 10)')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=30,
                       help='Request timeout in seconds (default: 30)')
    
    parser.add_argument('--delay',
                       type=float,
                       default=0,
                       help='Delay between requests in seconds (default: 0)')
    
    parser.add_argument('--rate-limit',
                       type=int,
                       help='Maximum requests per second')
    
    # Network options
    parser.add_argument('--proxy',
                       help='Proxy URL (http://host:port or socks5://host:port)')
    
    parser.add_argument('--proxy-file',
                       help='File containing list of proxies')
    
    parser.add_argument('--user-agent',
                       help='Custom User-Agent string')
    
    parser.add_argument('--random-agent',
                       action='store_true',
                       help='Use random User-Agent for each request')
    
    parser.add_argument('--headers',
                       help='File containing custom HTTP headers')
    
    parser.add_argument('--cookies',
                       help='Cookies string (key=value;key2=value2)')
    
    # Authentication options
    parser.add_argument('--auth',
                       help='Authentication string (username:password)')
    
    parser.add_argument('--auth-type',
                       choices=['basic', 'digest', 'ntlm'],
                       default='basic',
                       help='Authentication type (default: basic)')
    
    parser.add_argument('--bearer-token',
                       help='Bearer token for API authentication')
    
    # Output options
    parser.add_argument('-o', '--output',
                       help='Output file/directory for reports')
    
    parser.add_argument('--report-format',
                       nargs='+',
                       choices=['json', 'html', 'pdf', 'markdown', 'csv', 'xml'],
                       default=['json', 'html'],
                       help='Report format(s) (default: json html)')
    
    parser.add_argument('--no-report',
                       action='store_true',
                       help='Disable report generation')
    
    # Reconnaissance options
    parser.add_argument('--recon',
                       nargs='*',
                       choices=['subdomains', 'ports', 'directories', 'tech', 'all'],
                       help='Reconnaissance modules to run')
    
    parser.add_argument('--wordlist',
                       help='Custom wordlist for directory bruteforce')
    
    # WAF options
    parser.add_argument('--detect-waf',
                       action='store_true',
                       help='Detect and fingerprint WAF')
    
    parser.add_argument('--waf-bypass',
                       action='store_true',
                       help='Attempt WAF bypass techniques')
    
    # Integration options
    parser.add_argument('--slack-webhook',
                       help='Slack webhook URL for notifications')
    
    parser.add_argument('--discord-webhook',
                       help='Discord webhook URL for notifications')
    
    parser.add_argument('--telegram-token',
                       help='Telegram bot token for notifications')
    
    parser.add_argument('--telegram-chat-id',
                       help='Telegram chat ID for notifications')
    
    parser.add_argument('--submit-hackerone',
                       action='store_true',
                       help='Submit findings to HackerOne')
    
    parser.add_argument('--program',
                       help='Bug bounty program name')
    
    # Behavioral options
    parser.add_argument('--stealth',
                       action='store_true',
                       help='Enable stealth mode (slower but more careful)')
    
    parser.add_argument('--aggressive',
                       action='store_true',
                       help='Enable aggressive mode (faster but noisier)')
    
    parser.add_argument('--ethical-mode',
                       action='store_true',
                       default=True,
                       help='Enable ethical mode (no destructive tests)')
    
    # Database options
    parser.add_argument('--save-to-db',
                       action='store_true',
                       default=True,
                       help='Save results to database')
    
    parser.add_argument('--compare-previous',
                       action='store_true',
                       help='Compare with previous scan results')
    
    # Misc options
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug mode')
    
    parser.add_argument('--quiet',
                       action='store_true',
                       help='Minimal output (only results)')
    
    parser.add_argument('--version',
                       action='version',
                       version=f'AlBaTTaR BUGS v{__version__}')
    
    parser.add_argument('--update',
                       action='store_true',
                       help='Check for updates')
    
    parser.add_argument('--config',
                       help='Custom config file path')
    
    return parser.parse_args()


def display_legal_disclaimer():
    """Display legal disclaimer and get user consent"""
    disclaimer = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER ⚠️                   ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}This tool is designed for ETHICAL SECURITY TESTING ONLY.{Colors.RESET}

{Colors.GREEN}✅ LEGAL USES:{Colors.RESET}
   • Bug Bounty Programs
   • Authorized Penetration Testing
   • Testing your own applications
   • Security research with permission

{Colors.RED}❌ ILLEGAL USES:{Colors.RESET}
   • Testing without authorization
   • Unauthorized access to systems
   • Data theft or destruction
   • Any criminal activity

{Colors.CYAN}⚠️  The developer is NOT responsible for misuse of this tool.
⚠️  Always obtain written permission before testing any target.
⚠️  You are solely responsible for your actions.{Colors.RESET}

{Colors.BOLD}By using this tool, you agree to use it ethically and legally.{Colors.RESET}
"""
    
    # Check if disclaimer was already accepted
    disclaimer_file = Path.home() / '.albattar_bugs' / 'disclaimer_accepted'
    if disclaimer_file.exists():
        return True
    
    print(disclaimer)
    response = input(f"\n{Colors.YELLOW}Do you accept these terms? (yes/no): {Colors.RESET}").lower()
    
    if response in ['yes', 'y']:
        # Create directory and save acceptance
        disclaimer_file.parent.mkdir(parents=True, exist_ok=True)
        disclaimer_file.write_text('accepted')
        print(f"{Colors.GREEN}✅ Terms accepted. Continuing...{Colors.RESET}\n")
        return True
    else:
        print(f"{Colors.RED}❌ Terms not accepted. Exiting...{Colors.RESET}")
        return False


def load_config(config_path=None):
    """Load configuration from file"""
    if config_path is None:
        config_path = Path(__file__).parent / 'config.json'
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        log_warning(f"Config file not found: {config_path}")
        return {}
    except json.JSONDecodeError as e:
        log_error(f"Invalid JSON in config file: {e}")
        return {}


def validate_target(target):
    """Validate target URL or domain"""
    validator = TargetValidator()
    return validator.validate(target)


def main():
    """Main function"""
    try:
        # Display banner
        if not any(arg in sys.argv for arg in ['--quiet', '--help', '-h', '--version']):
            display_banner()
        
        # Parse arguments
        args = parse_arguments()
        
        # Setup logger
        log_level = 'DEBUG' if args.debug else ('INFO' if args.verbose else 'WARNING')
        setup_logger(level=log_level, quiet=args.quiet)
        
        # Check for updates
        if args.update:
            from utils.version_checker import check_for_updates
            check_for_updates(__version__)
            return 0
        
        # Display legal disclaimer
        if not args.quiet:
            if not display_legal_disclaimer():
                return 1
        
        # Load configuration
        config = load_config(args.config)
        
        # Validate target(s)
        targets = []
        if args.url:
            log_info(f"🎯 Target: {args.url}")
            if validate_target(args.url):
                targets.append(args.url)
                log_success("✅ Target is valid and reachable")
            else:
                log_error("❌ Target validation failed")
                return 1
        
        elif args.list:
            log_info(f"📋 Loading targets from: {args.list}")
            try:
                with open(args.list, 'r') as f:
                    for line in f:
                        target = line.strip()
                        if target and not target.startswith('#'):
                            if validate_target(target):
                                targets.append(target)
                log_success(f"✅ Loaded {len(targets)} valid targets")
            except FileNotFoundError:
                log_error(f"❌ Target list file not found: {args.list}")
                return 1
        
        if not targets:
            log_error("❌ No valid targets to scan")
            return 1
        
        # Initialize scan orchestrator
        orchestrator = ScanOrchestrator(
            targets=targets,
            config=config,
            args=vars(args)
        )
        
        # Run scan
        log_info("🚀 Starting scan...")
        results = orchestrator.run()
        
        # Display results summary
        if not args.quiet:
            display_results_summary(results)
        
        # Generate reports
        if not args.no_report:
            from reports.report_generator import ReportGenerator
            reporter = ReportGenerator(results, args)
            reporter.generate_reports()
        
        log_success("✅ Scan completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        log_warning("\n⚠️  Scan interrupted by user")
        return 130
    
    except Exception as e:
        log_error(f"❌ Fatal error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


def display_results_summary(results):
    """Display a summary of scan results"""
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'SCAN RESULTS SUMMARY':^70}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")
    
    # Count vulnerabilities by severity
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for result in results.get('vulnerabilities', []):
        severity = result.get('severity', 'info').lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Display counts with colors
    total = sum(severity_counts.values())
    
    print(f"{Colors.RED}🔴 CRITICAL: {severity_counts['critical']}{Colors.RESET}")
    print(f"{Colors.ORANGE}🟠 HIGH:     {severity_counts['high']}{Colors.RESET}")
    print(f"{Colors.YELLOW}🟡 MEDIUM:   {severity_counts['medium']}{Colors.RESET}")
    print(f"{Colors.GREEN}🟢 LOW:      {severity_counts['low']}{Colors.RESET}")
    print(f"{Colors.CYAN}ℹ️  INFO:     {severity_counts['info']}{Colors.RESET}")
    print(f"\n{Colors.BOLD}📊 TOTAL:    {total}{Colors.RESET}")
    
    # Statistics
    stats = results.get('statistics', {})
    print(f"\n{Colors.BOLD}{'─'*70}{Colors.RESET}")
    print(f"{Colors.BOLD}STATISTICS:{Colors.RESET}")
    print(f"  ⏱️  Duration: {stats.get('duration', 'N/A')}")
    print(f"  📨 Total Requests: {stats.get('total_requests', 0):,}")
    print(f"  🎯 Endpoints Tested: {stats.get('endpoints_tested', 0):,}")
    if stats.get('ai_enabled'):
        print(f"  🧠 AI Tokens Used: {stats.get('ai_tokens_used', 0):,}")
    
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")


if __name__ == "__main__":
    sys.exit(main())
