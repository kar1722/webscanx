#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base Module Class

All scanning modules must inherit from this base class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """
    Abstract base class for all scanning modules
    
    All modules must:
    1. Define MODULE_NAME class attribute
    2. Implement run() method
    3. Optionally implement initialize() and cleanup() methods
    """
    
    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base module"
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        """
        Initialize module
        
        Args:
            config: Configuration manager
            state: Scan state manager
            http_client: HTTP client instance
            ai_analyzer: AI analyzer instance (optional)
        """
        self.config = config
        self.state = state
        self.http_client = http_client
        self.ai_analyzer = ai_analyzer
        self.logger = logging.getLogger(f"modules.{self.MODULE_NAME}")
        
        # Module-specific data
        self.findings: List[Dict[str, Any]] = []
        self.assets: List[Dict[str, Any]] = []
    
    async def initialize(self):
        """Optional initialization - override in subclass"""
        pass
    
    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        """
        Execute module - must be implemented by subclasses
        
        Returns:
            Dictionary containing module results
        """
        pass
    
    def cleanup(self):
        """Optional cleanup - override in subclass"""
        pass
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to module results"""
        self.findings.append(finding)
        self.logger.debug(f"Finding added: {finding.get('title', 'Unknown')}")
    
    def add_asset(self, asset: Dict[str, Any]):
        """Add an asset to module results"""
        self.assets.append(asset)
        self.logger.debug(f"Asset added: {asset.get('type', 'Unknown')} - {asset.get('value', 'Unknown')}")
    
    def get_results(self) -> Dict[str, Any]:
        """Get module results"""
        return {
            'module': self.MODULE_NAME,
            'findings': self.findings,
            'assets': self.assets,
            'success': True
        }
