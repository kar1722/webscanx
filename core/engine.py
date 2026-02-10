#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import sys
import time
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional, Type, Tuple, Set
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

from core.state import ScanState, ScanPhase, ScanStatus
from core.config import ConfigManager
from utils.http_client import HTTPClient
from utils.rate_limiter import RateLimiter
from dataclasses import asdict


def _import_modules_safely():

    modules = {}
    
    try:
        from modules.reconnaissance import ReconnaissanceModule
        modules['reconnaissance'] = ReconnaissanceModule
        logger.debug("✓ ReconnaissanceModule imported")
    except Exception as e:
        logger.error(f"✗ Failed to import ReconnaissanceModule: {e}")
        modules['reconnaissance'] = None
    
    try:
        from modules.discovery import DiscoveryModule
        modules['discovery'] = DiscoveryModule
        logger.debug("✓ DiscoveryModule imported")
    except Exception as e:
        logger.error(f"✗ Failed to import DiscoveryModule: {e}")
        modules['discovery'] = None
    
    try:
        from modules.vulnerability import VulnerabilityModule
        modules['vulnerability'] = VulnerabilityModule
        logger.debug("✓ VulnerabilityModule imported")
    except Exception as e:
        logger.error(f"✗ Failed to import VulnerabilityModule: {e}")
        modules['vulnerability'] = None
    
    try:
        from modules.waf_detection import WAFDetectionModule
        modules['waf_detection'] = WAFDetectionModule
        logger.debug("✓ WAFDetectionModule imported")
    except Exception as e:
        logger.error(f"✗ Failed to import WAFDetectionModule: {e}")
        modules['waf_detection'] = None
    
    try:
        from modules.evasion import EvasionModule
        modules['evasion'] = EvasionModule
        logger.debug("✓ EvasionModule imported")
    except Exception as e:
        logger.error(f"✗ Failed to import EvasionModule: {e}")
        modules['evasion'] = None
    
    try:
        from modules.crawler import SmartCrawler
        modules['crawler'] = SmartCrawler
        logger.debug("✓ SmartCrawler imported")
    except Exception as e:
        logger.warning(f"⚠ SmartCrawler not available: {e}")
        modules['crawler'] = None
    
    return modules

_AVAILABLE_MODULES = _import_modules_safely()

class SimpleOutput:

    
    COLORS = {
        'info': '\033[94m',    
        'success': '\033[92m',  
        'warning': '\033[93m',  
        'error': '\033[91m',    
        'critical': '\033[95m', 
        'reset': '\033[0m',
    }
    
    @staticmethod
    def timestamp():

        return datetime.now().strftime("%H:%M:%S")
    
    @classmethod
    def print(cls, level: str, message: str, module: str = ""):

        color = cls.COLORS.get(level, cls.COLORS['info'])
        time_str = cls.timestamp()
        
        if module:
            module_str = f"[{module.upper():<12}] "
        else:
            module_str = ""
        
        if not sys.stdout.isatty():
            color = ''
            reset = ''
        else:
            reset = cls.COLORS['reset']
        
        print(f"{color}[{time_str}] [{level.upper():<7}] {module_str}{message}{reset}")
    
    @classmethod
    def info(cls, message: str, module: str = ""):
        cls.print('info', message, module)
    
    @classmethod
    def success(cls, message: str, module: str = ""):
        cls.print('success', message, module)
    
    @classmethod
    def warning(cls, message: str, module: str = ""):
        cls.print('warning', message, module)
    
    @classmethod
    def error(cls, message: str, module: str = ""):
        cls.print('error', message, module)
    
    @classmethod
    def critical(cls, message: str, module: str = ""):
        cls.print('critical', message, module)
    
    @classmethod
    def banner(cls, text: str):

        print("\n" + "=" * 70)
        print(f" {text}")
        print("=" * 70 + "\n")
    
    @classmethod
    def section(cls, text: str):

        print(f"\n{'-' * 60}")
        print(f" {text}")
        print(f"{'-' * 60}")
    
    @classmethod
    def stats_line(cls, label: str, value: str, color: str = "info"):

        color_code = cls.COLORS.get(color, cls.COLORS['info'])
        reset = cls.COLORS['reset'] if sys.stdout.isatty() else ''
        print(f"{color_code}[*]{reset} {label}: {value}")

class ModuleRegistry:
    
    def __init__(self):
        self._modules: Dict[str, Type] = {}
        self._register_all_modules()
    
    def _register_all_modules(self):

        global _AVAILABLE_MODULES
        
        for name, module_class in _AVAILABLE_MODULES.items():
            if module_class is not None:
                self._modules[name] = module_class
                logger.debug(f"Registered module: {name}")
            else:
                logger.warning(f"Module class is None: {name}")
    
    def register(self, name: str, module_class: Type):

        self._modules[name] = module_class
        logger.info(f"Manually registered module: {name}")
    
    def get(self, name: str) -> Optional[Type]:

        return self._modules.get(name)
    
    def list_modules(self) -> List[str]:

        return list(self._modules.keys())
    
    def is_available(self, name: str) -> bool:

        return name in self._modules and self._modules[name] is not None

class ScanEngine:

    SCAN_PHASES = [
        (ScanPhase.WAF_DETECTION, ['waf_detection'], "WAF Detection"),      
        (ScanPhase.EVASION, ['evasion'], "Evasion Testing"),               
        (ScanPhase.RECONNAISSANCE, ['reconnaissance'], "Reconnaissance"),  
        (ScanPhase.CRAWLER, ['crawler'], "Crawling"),                      
        (ScanPhase.DISCOVERY, ['discovery'], "Discovery"),                  
        (ScanPhase.VULNERABILITY_SCAN, ['vulnerability'], "Vulnerability Scan"), 
    ]
    
    def __init__(self, config: ConfigManager, state: ScanState, ai_analyzer=None):
        
        self.config = config
        self.state = state
        self.ai_analyzer = ai_analyzer
        
        self.http_client: Optional[HTTPClient] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.module_registry = ModuleRegistry()
        
        self.modules: Dict[str, Any] = {}
        self.module_results: Dict[str, Dict] = {}
        
        self.waf_evader = None
        self.stealth_browser = None
        self.evasion_enabled = config.get('scan.evasion', False)
        self.stealth_enabled = config.get('scan.stealth', False)
        
        self.output = SimpleOutput()
        
        self.verbose = config.get('scan.verbose', False)
        
        self._stop_requested = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        
        self.phase_results: Dict[str, Any] = {}
        
        logger.debug("ScanEngine initialized")
    
    async def initialize(self):

        try:

            self.state.statistics.start_time = datetime.now()
            
            self.output.banner("WebScanX Security Scanner v3.0")
            self.output.info(f"Target: {self.config.get('target')}")
            self.output.info(f"Mode: {self.config.get('scan.mode', 'standard')}")
            self.output.info(f"Modules available: {', '.join(self.module_registry.list_modules())}")
            
            await self._init_http_client()
            
            await self._init_rate_limiter()
            
            await self._init_modules()
            
            await self._init_evasion_tools()
            
            self.output.success("Engine initialization completed successfully")
            
        except Exception as e:
            self.output.error(f"Engine initialization failed: {e}")
            logger.error(f"Engine initialization failed: {e}", exc_info=True)
            raise
    
    async def _init_http_client(self):

        self.output.info("Initializing HTTP client...")
        self.http_client = HTTPClient(self.config)
        await self.http_client.initialize()
        self.output.success("HTTP client initialized")
    
    async def _init_rate_limiter(self):

        rate_limit = self.config.get('scan.rate_limit')
        if rate_limit:
            self.rate_limiter = RateLimiter(rate_limit)
            self.output.info(f"Rate limit: {rate_limit} req/sec")
    
    async def _init_modules(self):

        self.output.info("Initializing modules...")
        
        enabled_modules = self._get_enabled_modules()
        self.output.info(f"Enabled modules: {', '.join(enabled_modules)}")
        
        initialized_count = 0
        failed_modules = []
        
        for module_name in enabled_modules:
            try:
                success = await self._init_single_module(module_name)
                if success:
                    initialized_count += 1
                else:
                    failed_modules.append(module_name)
            except Exception as e:
                logger.error(f"Failed to initialize {module_name}: {e}")
                failed_modules.append(module_name)
        
        self.output.success(f"Initialized {initialized_count}/{len(enabled_modules)} modules")
        
        if failed_modules:
            self.output.warning(f"Failed modules: {', '.join(failed_modules)}")
    
    async def _init_single_module(self, module_name: str) -> bool:

        try:
            module_class = self.module_registry.get(module_name)
            
            if not module_class:
                self.output.error(f"Module class not found: {module_name}")
                return False
            
            instance = module_class(
                config=self.config,
                state=self.state,
                http_client=self.http_client,
                ai_analyzer=self.ai_analyzer
            )
            
            if hasattr(instance, 'initialize'):
                if asyncio.iscoroutinefunction(instance.initialize):
                    await instance.initialize()
                else:
                    instance.initialize()
            
            self.modules[module_name] = instance
            
            if self.verbose and hasattr(instance, 'verbose'):
                instance.verbose = True
            
            logger.info(f"✓ Module initialized: {module_name}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Module initialization failed: {module_name} - {e}")
            traceback.print_exc()
            return False
    
    async def _init_evasion_tools(self):

        if self.evasion_enabled:
            from core.waf_evader import SmartWAFEvader
            self.waf_evader = SmartWAFEvader()
            self.output.warning("WAF evasion enabled")
        
        if self.stealth_enabled:
            from core.stealth_browser import StealthBrowser
            self.stealth_browser = StealthBrowser(self.config)
            if await self.stealth_browser.initialize():
                self.output.warning("Stealth mode enabled")
    
    def _get_enabled_modules(self) -> List[str]:

        mode = self.config.get('scan.mode', 'standard')
        
        mode_configs = {
            'silent': ['reconnaissance', 'crawler'],
            'standard': ['reconnaissance', 'crawler', 'discovery', 'vulnerability'],
            'deep': ['reconnaissance', 'crawler', 'discovery', 'vulnerability', 'waf_detection', 'evasion'],
            'ai': ['reconnaissance', 'crawler', 'discovery', 'vulnerability', 'waf_detection', 'evasion'],
        }
        
        required = mode_configs.get(mode, mode_configs['standard'])
        
        enabled = []
        for module_name in required:
            if self.module_registry.is_available(module_name):
                enabled.append(module_name)
            else:
                self.output.warning(f"Module not available: {module_name}")
                
                if module_name == 'crawler' and not self.module_registry.is_available('crawler'):
                    self.output.warning("Crawler not available, will use fallback discovery")
        
        if not enabled:
            raise RuntimeError("No modules available for scanning!")
        
        return enabled
    
    async def execute(self) -> Dict[str, Any]:
        
        self.state.set_status(ScanStatus.RUNNING)
        execution_start = time.time()
        
        try:
            self.output.section("Starting Security Scan")
            
            for phase_enum, module_names, phase_name in self.SCAN_PHASES:

                if self._stop_requested:
                    self.output.warning("Stop requested, aborting scan")
                    break
                
                available_modules = [m for m in module_names if m in self.modules]
                
                if not available_modules:
                    logger.debug(f"Skipping phase {phase_name} - no modules available")
                    continue
                
                await self._execute_phase(phase_enum, available_modules, phase_name)
            
            if self.ai_analyzer and self.config.get('ai.enabled'):
                await self._run_ai_analysis()
            
            await self._complete_scan()
            
            return self._compile_results()
            
        except Exception as e:
            await self._handle_scan_error(e)
            raise
    
    async def _execute_phase(self, phase: ScanPhase, module_names: List[str], phase_name: str):
        
        phase_start = time.time()
        self.state.set_phase(phase)
        
        self.output.section(f"Starting {phase_name} Phase")
        self.output.info(f"Modules: {', '.join(module_names)}")
        
        phase_results = {
            'phase': phase_name,
            'modules': {},
            'start_time': datetime.now().isoformat(),
        }
        
        for module_name in module_names:
            if module_name not in self.modules:
                self.output.warning(f"Module {module_name} not initialized, skipping")
                continue
            
            module = self.modules[module_name]
            
            try:
                self.output.info(f"Running {module_name}...")
                
                result = await self._run_module_safely(module)
                
                phase_results['modules'][module_name] = {
                    'status': 'success',
                    'result': result,
                }
                
                self.module_results[module_name] = result
                
                self._print_module_summary(module_name, result)
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Module {module_name} failed: {error_msg}")
                traceback.print_exc()
                
                phase_results['modules'][module_name] = {
                    'status': 'failed',
                    'error': error_msg,
                }
        
        phase_duration = time.time() - phase_start
        phase_results['duration'] = phase_duration
        phase_results['end_time'] = datetime.now().isoformat()
        
        self.phase_results[phase_name] = phase_results
        
        self.output.info(f"{phase_name} phase completed in {phase_duration:.2f}s")
        
        successful = sum(1 for m in phase_results['modules'].values() if m.get('status') == 'success')
        total = len(phase_results['modules'])
        self.output.info(f"Successful modules: {successful}/{total}")
    
    async def _run_module_safely(self, module) -> Dict[str, Any]:
        
        await self._pause_event.wait()
        
        if self._stop_requested:
            return {'status': 'aborted'}
        
        start_time = time.time()
        
        if asyncio.iscoroutinefunction(module.run):
            result = await module.run()
        else:
            result = module.run()
        
        duration = time.time() - start_time
        
        if not isinstance(result, dict):
            result = {'data': result}
        
        result['_execution_time'] = duration
        
        return result
    
    def _print_module_summary(self, module_name: str, result: Dict):
        
        if not isinstance(result, dict):
            return
        
        stats = result.get('stats', {})
        
        lines = []
        
        if 'pages_crawled' in stats:
            lines.append(f"pages: {stats['pages_crawled']}")
        if 'injection_points' in stats:
            lines.append(f"injection points: {stats['injection_points']}")
        if 'assets' in result:
            lines.append(f"assets: {len(result['assets'])}")
        if 'findings' in result:
            lines.append(f"findings: {len(result['findings'])}")
        
        if lines:
            summary = ", ".join(lines)
            self.output.success(f"{module_name}: {summary}")
    
    async def _run_ai_analysis(self):
        
        if not self.ai_analyzer:
            return
        
        self.output.section("Running AI Analysis")
        
        try:
            start_time = time.time()
            
            if not self.ai_analyzer.http_client and self.http_client:
                await self.ai_analyzer.initialize(self.http_client)
            
            findings_analysis = await self.ai_analyzer.analyze_findings(
                self.state.findings
            )
            
            correlations = await self.ai_analyzer.correlate_findings(
                self.state.findings,
                self.state.assets
            )
            
            scan_data = self.state.to_dict()
            insights = await self.ai_analyzer.generate_insights(scan_data)
            
            for insight in insights:
                self.state.add_ai_insight(insight)
            
            duration = time.time() - start_time
            
            self.output.success(f"AI analysis completed in {duration:.2f}s")
            
            if correlations:
                self.output.info(f"Found {len(correlations)} correlations")
            
        except Exception as e:
            self.output.error(f"AI analysis failed: {e}")
            logger.error(f"AI analysis error: {e}", exc_info=True)
    
    async def _complete_scan(self):
        
        self.state.set_phase(ScanPhase.COMPLETED)
        self.state.set_status(ScanStatus.COMPLETED)
        self.state.statistics.end_time = datetime.now()
        
        total_duration = self.state.statistics.duration
        
        self.output.section("Scan Completed")
        
        self.output.stats_line("Scan duration", f"{total_duration:.2f} seconds")
        self.output.stats_line("Total requests", str(self.state.statistics.total_requests))
        self.output.stats_line("Successful requests", str(self.state.statistics.successful_requests))
        self.output.stats_line("Failed requests", str(self.state.statistics.failed_requests))
        self.output.stats_line("Payloads sent", str(self.state.statistics.payloads_sent))
        self.output.stats_line("Total findings", str(len(self.state.findings)))
        
        if self.state.findings:
            self.output.section("Vulnerabilities by Severity")
            
            severity_counts = {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
            }
            
            for finding in self.state.findings:
                sev = finding.severity.lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            for severity, count in severity_counts.items():
                if count > 0:
                    color = {
                        'critical': 'error',
                        'high': 'error',
                        'medium': 'warning',
                        'low': 'info',
                        'info': 'info'
                    }.get(severity, 'info')
                    
                    self.output.stats_line(
                        f"{severity.upper()}",
                        str(count),
                        color
                    )
            
            self.output.section("Top Findings")
            
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(
                self.state.findings,
                key=lambda f: severity_order.get(f.severity.lower(), 5)
            )
            
            for i, finding in enumerate(sorted_findings[:10], 1):
                color = severity_order.get(finding.severity.lower(), 5) < 2 and 'error' or 'warning'
                self.output.print(
                    color,
                    f"[{finding.severity.upper()}] {finding.title}",
                    "FINDING"
                )
                print(f"    URL: {finding.url}")
                print(f"    Category: {finding.category}")
                print()
        
        else:
            self.output.success("No vulnerabilities found")
        
        self.output.section("Phase Summary")
        for phase_name, phase_data in self.phase_results.items():
            duration = phase_data.get('duration', 0)
            modules_success = sum(
                1 for m in phase_data.get('modules', {}).values()
                if m.get('status') == 'success'
            )
            modules_total = len(phase_data.get('modules', {}))
            self.output.info(f"{phase_name}: {duration:.2f}s ({modules_success}/{modules_total} modules)")
    
    async def _handle_scan_error(self, error: Exception):
        
        self.state.set_phase(ScanPhase.ERROR)
        self.state.set_status(ScanStatus.FAILED)
        self.state.add_error(str(error))
        
        self.output.section("Scan Failed")
        self.output.error(f"Error: {str(error)}")
        
        logger.error(f"Scan execution failed: {error}", exc_info=True)
    
    def _compile_results(self) -> Dict[str, Any]:
        
        severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.state.findings:
            sev = finding.severity.lower()
            if sev in severity_dist:
                severity_dist[sev] += 1
        
        return {
            'scan_info': {
                'scan_id': self.state.scan_id,
                'target': self.state.target,
                'mode': self.state.mode,
                'start_time': self.state.statistics.start_time.isoformat() if self.state.statistics.start_time else None,
                'end_time': self.state.statistics.end_time.isoformat() if self.state.statistics.end_time else None,
                'duration_seconds': self.state.statistics.duration,
            },
            'statistics': {
                **self.state.statistics.to_dict(),
                'severity_distribution': severity_dist,
            },
            'findings': [f.to_dict() for f in self.state.findings],
            'assets': [a.to_dict() for a in self.state.assets],
            'technologies': self.state.technologies,
            'ai_insights': self.state.ai_insights,
            'phase_results': self.phase_results,
            'module_results': self.module_results,
            'summary': {
                'total_findings': len(self.state.findings),
                'critical': severity_dist['critical'],
                'high': severity_dist['high'],
                'medium': severity_dist['medium'],
                'low': severity_dist['low'],
                'info': severity_dist['info'],
                'endpoints_discovered': len(self.state.discovered_endpoints),
                'parameters_found': sum(
                    len(p) for p in self.state.discovered_parameters.values()
                ),
                'technologies_detected': len(self.state.technologies),
                'phases_completed': len(self.phase_results),
                'modules_executed': len(self.module_results),
            }
        }
    
    
    def pause(self):
    
        self._pause_event.clear()
        self.state.set_status(ScanStatus.PAUSED)
        self.output.warning("Scan paused")
        logger.info("Scan paused")
    
    def resume(self):

        self._pause_event.set()
        self.state.set_status(ScanStatus.RUNNING)
        self.output.success("Scan resumed")
        logger.info("Scan resumed")
    
    def stop(self):

        self._stop_requested = True
        self.output.warning("Stop requested")
        logger.info("Stop requested")
    

    
    async def cleanup(self):

        self.output.info("Cleaning up resources...")
        
        try:

            for name, module in self.modules.items():
                if hasattr(module, 'cleanup'):
                    try:
                        if asyncio.iscoroutinefunction(module.cleanup):
                            await module.cleanup()
                        else:
                            module.cleanup()
                    except Exception as e:
                        logger.error(f"Module cleanup error ({name}): {e}")

            if self.http_client:
                await self.http_client.cleanup()
            
            if self.stealth_browser:
                await self.stealth_browser.cleanup()
            
            self.output.success("Cleanup completed")
            logger.info("Engine cleanup complete")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    async def save_state(self):

        try:
            state_file = f"scan_state_{self.state.scan_id}.json"
            self.state.save(state_file)
            self.output.info(f"Scan state saved to {state_file}")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
