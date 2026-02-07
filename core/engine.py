#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import importlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
from datetime import datetime
import logging

from core.state import ScanState, ScanPhase, ScanStatus
from utils.http_client import HTTPClient
from utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class ModuleRegistry:

    def __init__(self):
        self._modules: Dict[str, Type] = {}
        self._instances: Dict[str, Any] = {}
    
    def register(self, name: str, module_class: Type):

        self._modules[name] = module_class
        logger.debug(f"Module registered: {name}")
    
    def get(self, name: str) -> Optional[Type]:

        return self._modules.get(name)
    
    def get_instance(self, name: str) -> Optional[Any]:

        return self._instances.get(name)
    
    def create_instance(self, name: str, *args, **kwargs) -> Optional[Any]:

        module_class = self.get(name)
        if module_class:
            instance = module_class(*args, **kwargs)
            self._instances[name] = instance
            return instance
        return None
    
    def list_modules(self) -> List[str]:

        return list(self._modules.keys())
    
    def discover_modules(self, modules_path: Path):
        
        if not modules_path.exists():
            logger.warning(f"Modules path not found: {modules_path}")
            return
        
        for file_path in modules_path.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
            
            try:
                module_name = f"modules.{file_path.stem}"
                module = importlib.import_module(module_name)
                
                # Look for module classes
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        hasattr(attr, 'MODULE_NAME') and
                        hasattr(attr, 'run')):
                        self.register(attr.MODULE_NAME, attr)
                        
            except Exception as e:
                logger.error(f"Failed to load module {file_path}: {e}")


class ScanEngine:

    def __init__(self, config, state: ScanState, ai_analyzer=None):
       
        self.config = config
        self.state = state
        self.ai_analyzer = ai_analyzer
        
        # Core components
        self.http_client: Optional[HTTPClient] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.module_registry = ModuleRegistry()
        
        # Module instances
        self.modules: Dict[str, Any] = {}
        
        # Execution control
        self._stop_requested = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        
        logger.debug("Scan engine initialized")
    
    async def initialize(self):

        try:
            # Initialize HTTP client
            self.http_client = HTTPClient(self.config)
            await self.http_client.initialize()
            
            # Initialize rate limiter
            rate_limit = self.config.get('scan.rate_limit')
            if rate_limit:
                self.rate_limiter = RateLimiter(rate_limit)
            
            # Discover and load modules
            modules_path = Path(__file__).parent.parent / "modules"
            self.module_registry.discover_modules(modules_path)
            
            # Manually register analysis module from AI components
            try:
                from ai.analyzer import AIAnalyzer
                # Create a wrapper class that follows the BaseModule interface
                class AnalysisModuleWrapper:
                    MODULE_NAME = "analysis"
                    MODULE_DESCRIPTION = "AI-powered analysis module"
                    
                    def __init__(self, config, state, http_client, ai_analyzer=None):
                        self.config = config
                        self.state = state
                        self.http_client = http_client
                        self.ai_analyzer = ai_analyzer or AIAnalyzer(config)
                        self.logger = logging.getLogger("modules.analysis")
                    
                    async def initialize(self):

                        if not self.ai_analyzer.http_client and self.http_client:
                            await self.ai_analyzer.initialize(self.http_client)
                    
                    async def run(self) -> Dict[str, Any]:

                        self.logger.info("Running AI analysis module")
                        
                        try:
                            # Analyze findings
                            findings_analysis = await self.ai_analyzer.analyze_findings(
                                self.state.findings
                            )
                            
                            # Correlate findings
                            correlations = await self.ai_analyzer.correlate_findings(
                                self.state.findings,
                                self.state.assets
                            )
                            
                            # Generate insights
                            scan_data = self.state.to_dict()
                            insights = await self.ai_analyzer.generate_insights(scan_data)
                            
                            # Add to state
                            for insight in insights:
                                self.state.add_ai_insight(insight)
                            
                            self.logger.info("AI analysis complete")
                            return {
                                'module': self.MODULE_NAME,
                                'success': True,
                                'analysis': findings_analysis,
                                'correlations': [asdict(c) for c in correlations],
                                'insights': insights
                            }
                            
                        except Exception as e:
                            self.logger.error(f"AI analysis failed: {e}")
                            return {
                                'module': self.MODULE_NAME,
                                'success': False,
                                'error': str(e)
                            }
                    
                    def cleanup(self):

                        pass
                
                # Register the wrapper class
                self.module_registry.register("analysis", AnalysisModuleWrapper)
                logger.info("Manually registered analysis module")
                
            except Exception as e:
                logger.warning(f"Failed to register analysis module: {e}")
            
            # Initialize enabled modules
            await self._initialize_modules()
            
            logger.info("Scan engine initialization complete")
            
        except Exception as e:
            logger.error(f"Engine initialization failed: {e}")
            raise
    
    async def _initialize_modules(self):

        enabled_modules = self._get_enabled_modules()
        
        for module_name in enabled_modules:
            try:
                module_class = self.module_registry.get(module_name)
                if module_class:
                    instance = module_class(
                        config=self.config,
                        state=self.state,
                        http_client=self.http_client,
                        ai_analyzer=self.ai_analyzer
                    )
                    
                    if hasattr(instance, 'initialize'):
                        await instance.initialize()
                    
                    self.modules[module_name] = instance
                    logger.info(f"Module initialized: {module_name}")
                    
            except Exception as e:
                logger.error(f"Failed to initialize module {module_name}: {e}")
    
    def _get_enabled_modules(self) -> List[str]:

        mode = self.config.get('scan.mode', 'standard')
        
        # Define module sets for each mode
        module_sets = {
            'silent': ['reconnaissance', 'technology', 'waf_detection'],
            'standard': ['reconnaissance', 'discovery', 'technology', 
                        'waf_detection', 'vulnerability'],
            'deep': ['reconnaissance', 'discovery', 'technology',
                    'waf_detection', 'vulnerability', 'ssl', 'analysis'],
            'ai': ['reconnaissance', 'discovery', 'technology',
                   'waf_detection', 'vulnerability', 'ssl', 'analysis']
        }
        
        # Get base module set for mode
        base_modules = module_sets.get(mode, module_sets['standard'])
        
        # Apply configuration overrides
        enabled = []
        for module in base_modules:
            if self.config.is_module_enabled(module):
                enabled.append(module)
        
        return enabled
    
    async def execute(self) -> Dict[str, Any]:
        
        self.state.set_status(ScanStatus.RUNNING)
        self.state.statistics.start_time = datetime.now()
        
        try:
            # Phase 1: Reconnaissance
            await self._run_phase(ScanPhase.RECONNAISSANCE, ['reconnaissance'])
            
            # Phase 2: Discovery
            await self._run_phase(ScanPhase.DISCOVERY, ['discovery'])
            
            # Phase 3: Vulnerability Scanning
            await self._run_phase(ScanPhase.VULNERABILITY_SCAN, ['vulnerability'])
            
            # Phase 4: SSL Analysis (if enabled and in deep mode)
            if 'ssl' in self.modules and self.config.get('scan.mode') in ['deep', 'ai']:
                await self._run_phase(ScanPhase.ANALYSIS, ['ssl'])
            
            # Phase 5: AI Analysis (if enabled)
            if self.ai_analyzer and self.config.get('ai.enabled'):
                await self._run_ai_analysis()
            
            # Complete
            self.state.set_phase(ScanPhase.COMPLETED)
            self.state.set_status(ScanStatus.COMPLETED)
            self.state.set_progress(100.0)
            self.state.statistics.end_time = datetime.now()
            
            return self._compile_results()
            
        except Exception as e:
            self.state.set_phase(ScanPhase.ERROR)
            self.state.set_status(ScanStatus.FAILED)
            self.state.add_error(str(e))
            logger.error(f"Scan execution failed: {e}", exc_info=True)
            raise
    
    async def _run_phase(self, phase: ScanPhase, module_names: List[str]):
        
        self.state.set_phase(phase)
        logger.info(f"Starting phase: {phase.value}")
        
        phase_modules = [self.modules.get(m) for m in module_names if m in self.modules]
        
        if not phase_modules:
            logger.warning(f"No modules available for phase: {phase.value}")
            return
        
        # Execute modules concurrently
        tasks = []
        for module in phase_modules:
            task = asyncio.create_task(self._run_module(module))
            tasks.append(task)
        
        # Wait for all modules to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for module, result in zip(phase_modules, results):
            if isinstance(result, Exception):
                logger.error(f"Module {module.__class__.__name__} failed: {result}")
                self.state.add_error(str(result), {'module': module.__class__.__name__})
            else:
                logger.info(f"Module {module.__class__.__name__} completed")
        
        # Update progress
        self._update_progress()
    
    async def _run_module(self, module):
        
        try:
            # Wait if paused
            await self._pause_event.wait()
            
            # Check for stop request
            if self._stop_requested:
                return
            
            # Execute module
            if asyncio.iscoroutinefunction(module.run):
                result = await module.run()
            else:
                result = module.run()
            
            return result
            
        except Exception as e:
            logger.error(f"Module execution error: {e}")
            raise
    
    async def _run_ai_analysis(self):

        if not self.ai_analyzer:
            return
        
        logger.info("Running AI analysis")
        
        try:
            # Analyze findings
            if not self.ai_analyzer.http_client and self.http_client:
                await self.ai_analyzer.initialize(self.http_client)
            
            findings_analysis = await self.ai_analyzer.analyze_findings(
                self.state.findings
            )
            
            # Correlate findings
            correlations = await self.ai_analyzer.correlate_findings(
                self.state.findings,
                self.state.assets
            )
            
            # Generate insights
            scan_data = self.state.to_dict()
            insights = await self.ai_analyzer.generate_insights(scan_data)
            
            # Add to state
            for insight in insights:
                self.state.add_ai_insight(insight)
            
            logger.info("AI analysis complete")
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
    
    def _update_progress(self):

        phase_weights = {
            ScanPhase.INITIALIZING: 0,
            ScanPhase.RECONNAISSANCE: 20,
            ScanPhase.DISCOVERY: 40,
            ScanPhase.VULNERABILITY_SCAN: 70,
            ScanPhase.ANALYSIS: 90,
            ScanPhase.REPORTING: 95,
            ScanPhase.COMPLETED: 100
        }
        
        current_weight = phase_weights.get(self.state.phase, 0)
        self.state.set_progress(current_weight)
    
    def _compile_results(self) -> Dict[str, Any]:

        return {
            'scan_info': {
                'scan_id': self.state.scan_id,
                'target': self.state.target,
                'mode': self.state.mode,
                'start_time': self.state.statistics.start_time.isoformat(),
                'end_time': self.state.statistics.end_time.isoformat() if self.state.statistics.end_time else None,
                'duration_seconds': self.state.statistics.duration
            },
            'statistics': self.state.statistics.to_dict(),
            'findings': [f.to_dict() for f in self.state.findings],
            'assets': [a.to_dict() for a in self.state.assets],
            'technologies': self.state.technologies,
            'ai_insights': self.state.ai_insights,
            'summary': {
                'total_findings': len(self.state.findings),
                'critical': self.state.statistics.critical_findings,
                'high': self.state.statistics.high_findings,
                'medium': self.state.statistics.medium_findings,
                'low': self.state.statistics.low_findings,
                'info': self.state.statistics.info_findings,
                'endpoints_discovered': len(self.state.discovered_endpoints),
                'parameters_found': sum(
                    len(p) for p in self.state.discovered_parameters.values()
                ),
                'technologies_detected': len(self.state.technologies)
            }
        }
    
    # Control Methods
    
    def pause(self):

        self._pause_event.clear()
        self.state.set_status(ScanStatus.PAUSED)
        logger.info("Scan paused")
    
    def resume(self):

        self._pause_event.set()
        self.state.set_status(ScanStatus.RUNNING)
        logger.info("Scan resumed")
    
    def stop(self):

        self._stop_requested = True
        logger.info("Stop requested")
    
    async def save_state(self):

        state_file = Path(self.config.get('report.output_dir', './reports')) / f"{self.state.scan_id}.state"
        state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state.save(str(state_file))
    
    async def cleanup(self):

        try:
            # Cleanup modules
            for name, module in self.modules.items():
                if hasattr(module, 'cleanup'):
                    try:
                        if asyncio.iscoroutinefunction(module.cleanup):
                            await module.cleanup()
                        else:
                            module.cleanup()
                    except Exception as e:
                        logger.error(f"Module cleanup error ({name}): {e}")
            
            # Cleanup HTTP client
            if self.http_client:
                await self.http_client.cleanup()
            
            logger.info("Engine cleanup complete")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
