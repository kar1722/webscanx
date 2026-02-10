#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         WebScanX - Web Security Scanner                      ║
║                    Advanced Web Application Security Testing Tool              ║
║                         Designed for Kali Linux                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author: Security Research Team
Version: 1.0.0
License: MIT

Description:
    WebScanX is a comprehensive web application security testing framework
    with AI-powered analysis, multiple scanning modes, and advanced vulnerability
    detection capabilities.

Features:
    - Multi-mode scanning (Silent, Standard, Deep, AI-Guided)
    - AI-powered correlation and analysis
    - Comprehensive attack surface mapping
    - WAF/IPS detection and analysis
    - Professional report generation
    - Modular and extensible architecture
"""

import sys
import os
import asyncio
import argparse
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

from core.engine import ScanEngine
from core.config import ConfigManager
from core.state import ScanState
from ai.analyzer import AIAnalyzer
from utils.logger import setup_logging
from utils.banner import display_banner
from utils.validator import validate_target
from reports.generator import ReportGenerator


class WebScanX:
    
    VERSION = "1.0.0"
    MODES = {
        'silent': 'Stealthy reconnaissance with minimal footprint',
        'standard': 'Balanced scanning with good coverage',
        'deep': 'In-depth analysis with correlation',
        'ai': 'AI-guided intelligent scanning'
    }
    
    def __init__(self):
        self.config: Optional[ConfigManager] = None
        self.engine: Optional[ScanEngine] = None
        self.ai_analyzer: Optional[AIAnalyzer] = None
        self.state: Optional[ScanState] = None
        self.report_gen: Optional[ReportGenerator] = None
        self.start_time: Optional[datetime] = None
        self.results: Dict[str, Any] = {}
        
    async def initialize(self, args: argparse.Namespace) -> bool:
        
        try:
            # Display banner
            if not args.no_banner:
                display_banner(self.VERSION)
            
            # Validate target
            if not await validate_target(args.target):
                print(f"{Fore.RED}[!] Invalid target specified")
                return False
            
            # Initialize configuration
            print(f"{Fore.CYAN}[*] Initializing configuration...")
            self.config = ConfigManager(args)
            
            # Setup logging
            setup_logging(
                level=self.config.get('logging.level', 'INFO'),
                log_file=self.config.get('logging.file')
            )
            logging.info(f"WebScanX v{self.VERSION} started")
            
            # Initialize state management
            self.state = ScanState(self.config)
            
            # Initialize AI analyzer if AI mode enabled
            if self.config.get('mode') == 'ai' or self.config.get('ai.enabled', False):
                print(f"{Fore.CYAN}[*] Initializing AI analysis engine...")
                self.ai_analyzer = AIAnalyzer(self.config)
                await self.ai_analyzer.initialize()
            
            # Initialize scan engine
            print(f"{Fore.CYAN}[*] Initializing scan engine...")
            self.engine = ScanEngine(self.config, self.state, self.ai_analyzer)
            await self.engine.initialize()
            
            # Initialize report generator
            self.report_gen = ReportGenerator(self.config)
            
            self.start_time = datetime.now()
            print(f"{Fore.GREEN}[+] Initialization complete")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] Initialization failed: {str(e)}")
            logging.error(f"Initialization error: {e}", exc_info=True)
            return False
    
    async def run_scan(self) -> Dict[str, Any]:
        
        try:
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.WHITE}                    STARTING SCAN")
            print(f"{Fore.CYAN}{'='*60}\n")
            
            # Execute scan phases
            self.results = await self.engine.execute()
            
            # AI-powered correlation if enabled
            if self.ai_analyzer:
                print(f"\n{Fore.CYAN}[*] Running AI-powered analysis...")
                ai_insights = await self.ai_analyzer.analyze_results(self.results)
                self.results['ai_analysis'] = ai_insights
            
            # Calculate scan duration
            duration = datetime.now() - self.start_time
            self.results['scan_metadata'] = {
                'start_time': self.start_time.isoformat(),
                'duration': str(duration),
                'mode': self.config.get('mode'),
                'target': self.config.get('target')
            }
            
            print(f"\n{Fore.GREEN}[+] Scan completed in {duration}")
            return self.results
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
            logging.warning("Scan interrupted by user")
            await self.handle_interrupt()
            return self.results
            
        except Exception as e:
            print(f"\n{Fore.RED}[!] Scan failed: {str(e)}")
            logging.error(f"Scan error: {e}", exc_info=True)
            raise
    
    async def generate_reports(self) -> List[str]:
       
        try:
            print(f"\n{Fore.CYAN}[*] Generating reports...")
            report_files = []
            
            formats = self.config.get('report.formats', ['json', 'html'])
            output_dir = self.config.get('report.output_dir', './reports')
            
            for fmt in formats:
                filepath = await self.report_gen.generate(
                    self.results, 
                    format=fmt,
                    output_dir=output_dir
                )
                report_files.append(filepath)
                print(f"{Fore.GREEN}[+] {fmt.upper()} report: {filepath}")
            
            return report_files
            
        except Exception as e:
            print(f"{Fore.RED}[!] Report generation failed: {str(e)}")
            logging.error(f"Report error: {e}", exc_info=True)
            return []
    
    async def handle_interrupt(self):

        print(f"{Fore.YELLOW}[*] Saving partial results...")
        if self.engine:
            await self.engine.save_state()
        print(f"{Fore.YELLOW}[*] Partial results saved. Use --resume to continue.")
    
    async def cleanup(self):

        try:
            if self.engine:
                await self.engine.cleanup()
            if self.ai_analyzer:
                await self.ai_analyzer.cleanup()
            logging.info("WebScanX cleanup complete")
        except Exception as e:
            logging.error(f"Cleanup error: {e}")


def create_argument_parser() -> argparse.ArgumentParser:
    
    parser = argparse.ArgumentParser(
        prog='webscanx',
        description='WebScanX - Advanced Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Silent mode - stealthy reconnaissance
  python3 webscanx.py -t https://example.com --mode silent
  
  # Standard scan with authentication
  python3 webscanx.py -t https://example.com --auth "Bearer token123"
  
  # Deep analysis with AI correlation
  python3 webscanx.py -t https://example.com --mode deep --ai
  
  # AI-guided scanning with custom wordlist
  python3 webscanx.py -t https://example.com --mode ai -w custom.txt
  
  # Full scan with all report formats
  python3 webscanx.py -t https://example.com --format json,html,pdf -o ./reports

Modes:
  silent    Minimal footprint, passive reconnaissance
  standard  Balanced scanning with good coverage
  deep      In-depth analysis with correlation
  ai        AI-guided intelligent scanning
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target URL or domain to scan'
    )
    
    # Scan mode
    parser.add_argument(
        '--mode',
        choices=['silent', 'standard', 'deep', 'ai'],
        default='standard',
        help='Scanning mode (default: standard)'
    )
    
    # AI options
    parser.add_argument(
        '--ai',
        action='store_true',
        help='Enable AI-powered analysis'
    )
    parser.add_argument(
        '--ai-model',
        default='default',
        help='AI model to use for analysis'
    )
    
    # Authentication
    parser.add_argument(
        '--auth',
        help='Authentication header or token'
    )
    parser.add_argument(
        '--cookie',
        help='Cookie string for authenticated scanning'
    )
    parser.add_argument(
        '--username',
        help='Username for basic authentication'
    )
    parser.add_argument(
        '--password',
        help='Password for basic authentication'
    )
    
    # Scan options
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of concurrent threads (default: 10)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0,
        help='Delay between requests in seconds'
    )
    parser.add_argument(
        '--user-agent',
        default='WebScanX/1.0',
        help='Custom User-Agent string'
    )
    parser.add_argument(
        '--proxy',
        help='Proxy URL (http://host:port)'
    )
    
    # Crawler
    parser.add_argument(
        '--crawl-depth',
        type=int,
        default=3,
        help='عمق الزحف (default: 3)'
    )
    parser.add_argument(
        '--max-pages',
        type=int,
        default=100,
        help='أقصى عدد صفحات للزحف (default: 100)'
    )
    parser.add_argument(
        '--concurrent-crawl',
        type=int,
        default=10,
        help='عدد طلبات الزحف المتزامنة (default: 10)'
    )
    parser.add_argument(
        '--no-robots',
        action='store_true',
        help='عدم احترام ملف robots.txt'
    )
    parser.add_argument(
        '--export-sitemap',
        action='store_true',
        help='تصدير خريطة الموقع'
    )
    
    # Wordlists
    parser.add_argument(
        '-w', '--wordlist',
        help='Custom wordlist for directory/file discovery'
    )
    parser.add_argument(
        '--payloads',
        help='Custom payload file for vulnerability testing'
    )
    
    # Scope options
    parser.add_argument(
        '--scope',
        choices=['domain', 'subdomain', 'url'],
        default='domain',
        help='Scan scope (default: domain)'
    )
    parser.add_argument(
        '--exclude',
        help='Paths to exclude (comma-separated)'
    )
    parser.add_argument(
        '--include',
        help='Paths to include (comma-separated)'
    )
    
    # Module selection
    parser.add_argument(
        '--modules',
        help='Modules to run (comma-separated, default: all)'
    )
    parser.add_argument(
        '--skip-modules',
        help='Modules to skip (comma-separated)'
    )
    
    # Report options
    parser.add_argument(
        '--format',
        default='json,html',
        help='Report formats (comma-separated: json,html,pdf,xml)'
    )
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='Output directory for reports'
    )
    parser.add_argument(
        '--template',
        help='Custom report template'
    )
    
    # Control options
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume interrupted scan'
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner display'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Increase verbosity level'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all output except errors'
    )
    parser.add_argument(
        '--config',
        help='Load configuration from file'
    )
    parser.add_argument(
        '--save-config',
        help='Save configuration to file'
    )
    
    # Advanced options
    parser.add_argument(
        '--rate-limit',
        type=int,
        help='Maximum requests per second'
    )
    parser.add_argument(
        '--retries',
        type=int,
        default=3,
        help='Number of retries for failed requests'
    )
    parser.add_argument(
        '--follow-redirects',
        action='store_true',
        default=True,
        help='Follow HTTP redirects'
    )
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        default=False,
        help='Verify SSL certificates'
    )
    
    return parser


async def main():

    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Create and run WebScanX
    scanner = WebScanX()
    
    try:
        # Initialize
        if not await scanner.initialize(args):
            sys.exit(1)
        
        # Run scan
        results = await scanner.run_scan()
        
        # Generate reports
        if results:
            report_files = await scanner.generate_reports()
            
            # Print summary
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.WHITE}                      SCAN SUMMARY")
            print(f"{Fore.CYAN}{'='*60}")
            print(f"{Fore.WHITE}Target: {args.target}")
            print(f"{Fore.WHITE}Mode: {args.mode}")
            print(f"{Fore.WHITE}Total Findings: {len(results.get('vulnerabilities', []))}")
            print(f"{Fore.WHITE}Reports Generated: {len(report_files)}")
            print(f"{Fore.CYAN}{'='*60}\n")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {str(e)}")
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
        
    finally:
        await scanner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user")
        sys.exit(0)
