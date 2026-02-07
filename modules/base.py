#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    
    MODULE_NAME: str = "base"
    MODULE_DESCRIPTION: str = "Base module"
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        
        self.config = config
        self.state = state
        self.http_client = http_client
        self.ai_analyzer = ai_analyzer
        self.logger = logging.getLogger(f"modules.{self.MODULE_NAME}")
        
        # Module-specific data
        self.findings: List[Dict[str, Any]] = []
        self.assets: List[Dict[str, Any]] = []
    
    async def initialize(self):

        pass
    
    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        
        pass
    
    def cleanup(self):

        pass
    
    def add_finding(self, finding: Dict[str, Any]):

        self.findings.append(finding)
        self.logger.debug(f"Finding added: {finding.get('title', 'Unknown')}")
    
    def add_asset(self, asset: Dict[str, Any]):

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
