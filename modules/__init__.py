# modules/__init__.py

from .base import BaseModule
from .reconnaissance import ReconnaissanceModule
from .discovery import DiscoveryModule
from .vulnerability import VulnerabilityModule
from .waf_detection import WAFDetectionModule
from .evasion import EvasionModule
from .crawler import SmartCrawler

__all__ = [
    'BaseModule',
    'ReconnaissanceModule',
    'DiscoveryModule',
    'VulnerabilityModule',
    'WAFDetectionModule',
    'EvasionModule',
    'SmartCrawler'
]
