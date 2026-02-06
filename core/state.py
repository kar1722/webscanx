#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan State Management Module

Manages the state of the scanning process, including:
- Current scan phase and progress
- Discovered assets and findings
- Statistics and metrics
- Pause/Resume functionality
"""

import json
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import logging

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Scan execution phases"""
    INITIALIZING = "initializing"
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    ERROR = "error"


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanStatistics:
    """Scan execution statistics"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    pages_scanned: int = 0
    endpoints_discovered: int = 0
    parameters_found: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'medium_findings': self.medium_findings,
            'low_findings': self.low_findings,
            'info_findings': self.info_findings,
            'pages_scanned': self.pages_scanned,
            'endpoints_discovered': self.endpoints_discovered,
            'parameters_found': self.parameters_found
        }
    
    @property
    def duration(self) -> float:
        """Calculate scan duration in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate request success rate"""
        if self.total_requests > 0:
            return (self.successful_requests / self.total_requests) * 100
        return 0.0


@dataclass
class DiscoveredAsset:
    """Represents a discovered asset"""
    type: str  # url, parameter, endpoint, technology, etc.
    value: str
    source: str  # How it was discovered
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'value': self.value,
            'source': self.source,
            'confidence': self.confidence,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class Finding:
    """Represents a security finding"""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str
    url: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    confidence: float = 1.0
    verified: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'url': self.url,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'confidence': self.confidence,
            'verified': self.verified,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }


class ScanState:
    """
    Manages the complete state of a scan
    
    Thread-safe state management for:
    - Scan progress and phase
    - Discovered assets
    - Security findings
    - Statistics
    - Pause/Resume support
    """
    
    def __init__(self, config):
        """
        Initialize scan state
        
        Args:
            config: ConfigurationManager instance
        """
        self.config = config
        self._lock = threading.RLock()
        
        # Scan metadata
        self.scan_id = self._generate_scan_id()
        self.target = config.get('target')
        self.mode = config.get('scan.mode', 'standard')
        
        # Status and phase
        self.status = ScanStatus.PENDING
        self.phase = ScanPhase.INITIALIZING
        self.progress = 0.0
        
        # Statistics
        self.statistics = ScanStatistics()
        
        # Data storage
        self.assets: List[DiscoveredAsset] = []
        self.findings: List[Finding] = []
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_parameters: Dict[str, Set[str]] = {}  # URL -> parameters
        self.technologies: Dict[str, Dict[str, Any]] = {}
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        
        # Module states
        self.module_states: Dict[str, Dict[str, Any]] = {}
        
        # AI insights
        self.ai_insights: List[Dict[str, Any]] = []
        
        # Errors and warnings
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        
        logger.debug(f"Scan state initialized: {self.scan_id}")
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        import random
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        return f"scan_{timestamp}_{random_suffix}"
    
    # Status Management
    
    def set_status(self, status: ScanStatus):
        """Update scan status"""
        with self._lock:
            self.status = status
            logger.debug(f"Scan status changed to: {status.value}")
    
    def set_phase(self, phase: ScanPhase):
        """Update scan phase"""
        with self._lock:
            self.phase = phase
            logger.info(f"Scan phase: {phase.value}")
    
    def set_progress(self, progress: float):
        """Update scan progress (0-100)"""
        with self._lock:
            self.progress = max(0.0, min(100.0, progress))
    
    # Asset Management
    
    def add_asset(self, asset: DiscoveredAsset):
        """Add discovered asset"""
        with self._lock:
            self.assets.append(asset)
            
            if asset.type == 'endpoint':
                self.discovered_endpoints.add(asset.value)
                self.statistics.endpoints_discovered = len(self.discovered_endpoints)
            elif asset.type == 'parameter':
                url = asset.metadata.get('url', 'unknown')
                if url not in self.discovered_parameters:
                    self.discovered_parameters[url] = set()
                self.discovered_parameters[url].add(asset.value)
                self.statistics.parameters_found = sum(
                    len(params) for params in self.discovered_parameters.values()
                )
            elif asset.type == 'technology':
                self.technologies[asset.value] = asset.metadata
            
            logger.debug(f"Asset discovered: {asset.type} - {asset.value}")
    
    def add_finding(self, finding: Finding):
        """Add security finding"""
        with self._lock:
            self.findings.append(finding)
            self.statistics.total_findings += 1
            
            # Update severity counts
            severity = finding.severity.lower()
            if severity == 'critical':
                self.statistics.critical_findings += 1
            elif severity == 'high':
                self.statistics.high_findings += 1
            elif severity == 'medium':
                self.statistics.medium_findings += 1
            elif severity == 'low':
                self.statistics.low_findings += 1
            else:
                self.statistics.info_findings += 1
            
            logger.info(f"Finding added: [{finding.severity.upper()}] {finding.title}")
    
    def add_visited_url(self, url: str):
        """Mark URL as visited"""
        with self._lock:
            self.visited_urls.add(url)
            self.statistics.pages_scanned = len(self.visited_urls)
    
    def is_url_visited(self, url: str) -> bool:
        """Check if URL has been visited"""
        with self._lock:
            return url in self.visited_urls
    
    # Request Statistics
    
    def increment_requests(self, success: bool = True):
        """Increment request counter"""
        with self._lock:
            self.statistics.total_requests += 1
            if success:
                self.statistics.successful_requests += 1
            else:
                self.statistics.failed_requests += 1
    
    # Module State Management
    
    def set_module_state(self, module: str, state: Dict[str, Any]):
        """Set module-specific state"""
        with self._lock:
            self.module_states[module] = state
    
    def get_module_state(self, module: str) -> Optional[Dict[str, Any]]:
        """Get module-specific state"""
        with self._lock:
            return self.module_states.get(module)
    
    # AI Insights
    
    def add_ai_insight(self, insight: Dict[str, Any]):
        """Add AI-generated insight"""
        with self._lock:
            self.ai_insights.append(insight)
            logger.debug(f"AI insight added: {insight.get('type', 'unknown')}")
    
    # Error Handling
    
    def add_error(self, error: str, context: Dict[str, Any] = None):
        """Add error to state"""
        with self._lock:
            self.errors.append({
                'error': error,
                'context': context or {},
                'timestamp': datetime.now().isoformat()
            })
            logger.error(f"Scan error: {error}")
    
    def add_warning(self, warning: str, context: Dict[str, Any] = None):
        """Add warning to state"""
        with self._lock:
            self.warnings.append({
                'warning': warning,
                'context': context or {},
                'timestamp': datetime.now().isoformat()
            })
            logger.warning(f"Scan warning: {warning}")
    
    # Serialization
    
    def save(self, filepath: str):
        """
        Save state to file for resume capability
        
        Args:
            filepath: Path to save state file
        """
        with self._lock:
            try:
                state_data = {
                    'scan_id': self.scan_id,
                    'target': self.target,
                    'mode': self.mode,
                    'status': self.status.value,
                    'phase': self.phase.value,
                    'progress': self.progress,
                    'statistics': self.statistics.to_dict(),
                    'assets': [a.to_dict() for a in self.assets],
                    'findings': [f.to_dict() for f in self.findings],
                    'visited_urls': list(self.visited_urls),
                    'discovered_endpoints': list(self.discovered_endpoints),
                    'discovered_parameters': {k: list(v) for k, v in self.discovered_parameters.items()},
                    'technologies': self.technologies,
                    'cookies': self.cookies,
                    'headers': self.headers,
                    'module_states': self.module_states,
                    'ai_insights': self.ai_insights,
                    'errors': self.errors,
                    'warnings': self.warnings
                }
                
                with open(filepath, 'wb') as f:
                    pickle.dump(state_data, f)
                
                logger.info(f"State saved to {filepath}")
                
            except Exception as e:
                logger.error(f"Failed to save state: {e}")
    
    def load(self, filepath: str):
        """
        Load state from file
        
        Args:
            filepath: Path to state file
        """
        with self._lock:
            try:
                with open(filepath, 'rb') as f:
                    state_data = pickle.load(f)
                
                self.scan_id = state_data.get('scan_id', self.scan_id)
                self.target = state_data.get('target', self.target)
                self.mode = state_data.get('mode', self.mode)
                self.status = ScanStatus(state_data.get('status', 'pending'))
                self.phase = ScanPhase(state_data.get('phase', 'initializing'))
                self.progress = state_data.get('progress', 0.0)
                
                # Restore collections
                self.visited_urls = set(state_data.get('visited_urls', []))
                self.discovered_endpoints = set(state_data.get('discovered_endpoints', []))
                self.discovered_parameters = {
                    k: set(v) for k, v in state_data.get('discovered_parameters', {}).items()
                }
                self.technologies = state_data.get('technologies', {})
                self.cookies = state_data.get('cookies', {})
                self.headers = state_data.get('headers', {})
                self.module_states = state_data.get('module_states', {})
                self.ai_insights = state_data.get('ai_insights', [])
                self.errors = state_data.get('errors', [])
                self.warnings = state_data.get('warnings', [])
                
                logger.info(f"State loaded from {filepath}")
                
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
    
    # Export Methods
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary"""
        with self._lock:
            return {
                'scan_id': self.scan_id,
                'target': self.target,
                'mode': self.mode,
                'status': self.status.value,
                'phase': self.phase.value,
                'progress': self.progress,
                'statistics': self.statistics.to_dict(),
                'assets': [a.to_dict() for a in self.assets],
                'findings': [f.to_dict() for f in self.findings],
                'technologies': self.technologies,
                'summary': {
                    'total_assets': len(self.assets),
                    'total_findings': len(self.findings),
                    'endpoints_discovered': len(self.discovered_endpoints),
                    'parameters_found': sum(len(p) for p in self.discovered_parameters.values()),
                    'technologies_detected': len(self.technologies)
                }
            }
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        with self._lock:
            return [f for f in self.findings if f.severity.lower() == severity.lower()]
    
    def get_findings_by_category(self, category: str) -> List[Finding]:
        """Get findings filtered by category"""
        with self._lock:
            return [f for f in self.findings if f.category.lower() == category.lower()]
    
    def get_high_confidence_findings(self, threshold: float = 0.8) -> List[Finding]:
        """Get findings with confidence above threshold"""
        with self._lock:
            return [f for f in self.findings if f.confidence >= threshold]
