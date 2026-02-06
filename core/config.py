#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration Management Module

Handles all configuration settings, command line arguments,
and configuration file operations for WebScanX.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Scan-specific configuration"""
    mode: str = 'standard'
    threads: int = 10
    timeout: int = 30
    delay: float = 0.0
    retries: int = 3
    rate_limit: Optional[int] = None
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_depth: int = 3
    scope: str = 'domain'


@dataclass
class AuthConfig:
    """Authentication configuration"""
    enabled: bool = False
    type: str = 'none'  # none, basic, bearer, cookie
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    cookie: Optional[str] = None
    header: Optional[str] = None


@dataclass
class AIConfig:
    """AI analysis configuration"""
    enabled: bool = False
    model: str = 'default'
    correlation_enabled: bool = True
    learning_enabled: bool = True
    confidence_threshold: float = 0.7
    max_context_size: int = 10000
    api_key: Optional[str] = None
    api_endpoint: Optional[str] = None


@dataclass
class ReportConfig:
    """Report generation configuration"""
    formats: List[str] = field(default_factory=lambda: ['json', 'html'])
    output_dir: str = './reports'
    template: Optional[str] = None
    include_evidence: bool = True
    include_remediation: bool = True
    severity_filter: Optional[List[str]] = None


@dataclass
class ModuleConfig:
    """Module-specific configuration"""
    enabled_modules: Optional[List[str]] = None
    disabled_modules: Optional[List[str]] = None
    wordlist_path: Optional[str] = None
    payload_path: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)


class ConfigManager:
    """
    Central Configuration Manager
    
    Manages all configuration aspects of WebScanX including:
    - Command line arguments
    - Configuration files (JSON/YAML)
    - Default settings
    - Runtime configuration updates
    """
    
    DEFAULT_CONFIG = {
        'scan': {
            'mode': 'standard',
            'threads': 10,
            'timeout': 30,
            'delay': 0.0,
            'retries': 3,
            'follow_redirects': True,
            'verify_ssl': False,
            'max_depth': 3,
            'scope': 'domain'
        },
        'auth': {
            'enabled': False,
            'type': 'none'
        },
        'ai': {
            'enabled': False,
            'model': 'default',
            'correlation_enabled': True,
            'learning_enabled': True,
            'confidence_threshold': 0.7,
            'max_context_size': 10000
        },
        'report': {
            'formats': ['json', 'html'],
            'output_dir': './reports',
            'include_evidence': True,
            'include_remediation': True
        },
        'logging': {
            'level': 'INFO',
            'file': None,
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'headers': {
            'User-Agent': 'WebScanX/1.0',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        },
        'modules': {
            'reconnaissance': True,
            'discovery': True,
            'vulnerability': True,
            'waf_detection': True,
            'technology': True,
            'ssl': True
        },
        'wordlists': {
            'directories': 'wordlists/dirs.txt',
            'files': 'wordlists/files.txt',
            'parameters': 'wordlists/params.txt',
            'payloads': 'wordlists/payloads.txt'
        },
        'exclusions': {
            'extensions': ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot'],
            'paths': ['/logout', '/exit', '/signout'],
            'status_codes': [404, 410, 500, 502, 503]
        },
        'vulnerability': {
            'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
            'test_sqli': True,
            'test_xss': True,
            'test_lfi': True,
            'test_rce': True,
            'test_redirect': True,
            'test_xxe': True,
            'test_ssrf': True,
            'test_idor': True
        }
    }
    
    def __init__(self, args=None):
        """
        Initialize configuration manager
        
        Args:
            args: Command line arguments from argparse
        """
        self._config = self._load_default_config()
        self._args = args
        
        # Load configuration from file if specified
        if args and hasattr(args, 'config') and args.config:
            self.load_from_file(args.config)
        
        # Apply command line arguments
        if args:
            self._apply_args(args)
        
        logger.debug("Configuration initialized")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return json.loads(json.dumps(self.DEFAULT_CONFIG))
    
    def _apply_args(self, args):
        """
        Apply command line arguments to configuration
        
        Args:
            args: Parsed command line arguments
        """
        # Target
        if hasattr(args, 'target') and args.target:
            self._config['target'] = args.target
        
        # Scan settings
        if hasattr(args, 'mode') and args.mode:
            self._config['scan']['mode'] = args.mode
        
        if hasattr(args, 'threads') and args.threads:
            self._config['scan']['threads'] = args.threads
        
        if hasattr(args, 'timeout') and args.timeout:
            self._config['scan']['timeout'] = args.timeout
        
        if hasattr(args, 'delay') and args.delay:
            self._config['scan']['delay'] = args.delay
        
        if hasattr(args, 'retries') and args.retries:
            self._config['scan']['retries'] = args.retries
        
        if hasattr(args, 'rate_limit') and args.rate_limit:
            self._config['scan']['rate_limit'] = args.rate_limit
        
        if hasattr(args, 'scope') and args.scope:
            self._config['scan']['scope'] = args.scope
        
        # Authentication
        if hasattr(args, 'auth') and args.auth:
            self._config['auth']['enabled'] = True
            self._config['auth']['type'] = 'bearer'
            self._config['auth']['header'] = args.auth
        
        if hasattr(args, 'cookie') and args.cookie:
            self._config['auth']['enabled'] = True
            self._config['auth']['type'] = 'cookie'
            self._config['auth']['cookie'] = args.cookie
        
        if hasattr(args, 'username') and args.username:
            self._config['auth']['enabled'] = True
            self._config['auth']['type'] = 'basic'
            self._config['auth']['username'] = args.username
        
        if hasattr(args, 'password') and args.password:
            self._config['auth']['password'] = args.password
        
        # AI settings
        if hasattr(args, 'ai') and args.ai:
            self._config['ai']['enabled'] = True
        
        if hasattr(args, 'ai_model') and args.ai_model:
            self._config['ai']['model'] = args.ai_model
        
        # Headers
        if hasattr(args, 'user_agent') and args.user_agent:
            self._config['headers']['User-Agent'] = args.user_agent
        
        # Proxy
        if hasattr(args, 'proxy') and args.proxy:
            self._config['proxy'] = args.proxy
        
        # Wordlists
        if hasattr(args, 'wordlist') and args.wordlist:
            self._config['wordlists']['directories'] = args.wordlist
        
        if hasattr(args, 'payloads') and args.payloads:
            self._config['wordlists']['payloads'] = args.payloads
        
        # Modules
        if hasattr(args, 'modules') and args.modules:
            enabled = args.modules.split(',')
            for module in self._config['modules']:
                self._config['modules'][module] = module in enabled
        
        if hasattr(args, 'skip_modules') and args.skip_modules:
            disabled = args.skip_modules.split(',')
            for module in disabled:
                if module in self._config['modules']:
                    self._config['modules'][module] = False
        
        # Report settings
        if hasattr(args, 'format') and args.format:
            self._config['report']['formats'] = args.format.split(',')
        
        if hasattr(args, 'output') and args.output:
            self._config['report']['output_dir'] = args.output
        
        if hasattr(args, 'template') and args.template:
            self._config['report']['template'] = args.template
        
        # Logging
        if hasattr(args, 'verbose') and args.verbose:
            levels = {0: 'WARNING', 1: 'INFO', 2: 'DEBUG'}
            self._config['logging']['level'] = levels.get(args.verbose, 'DEBUG')
        
        if hasattr(args, 'quiet') and args.quiet:
            self._config['logging']['level'] = 'ERROR'
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'scan.mode', 'auth.enabled')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key
            value: Value to set
        """
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        logger.debug(f"Config updated: {key} = {value}")
    
    def load_from_file(self, filepath: str):
        """
        Load configuration from file (JSON or YAML)
        
        Args:
            filepath: Path to configuration file
        """
        path = Path(filepath)
        
        if not path.exists():
            logger.warning(f"Config file not found: {filepath}")
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix in ['.yaml', '.yml']:
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            self._deep_update(self._config, data)
            logger.info(f"Configuration loaded from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
    
    def save_to_file(self, filepath: str):
        """
        Save current configuration to file
        
        Args:
            filepath: Path to save configuration
        """
        path = Path(filepath)
        
        try:
            with open(path, 'w', encoding='utf-8') as f:
                if path.suffix in ['.yaml', '.yml']:
                    yaml.dump(self._config, f, default_flow_style=False)
                else:
                    json.dump(self._config, f, indent=2)
            
            logger.info(f"Configuration saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save config file: {e}")
    
    def _deep_update(self, d: Dict, u: Dict):
        """
        Deep update dictionary
        
        Args:
            d: Base dictionary
            u: Update dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v
    
    def get_scan_config(self) -> ScanConfig:
        """Get scan configuration as dataclass"""
        return ScanConfig(**self._config.get('scan', {}))
    
    def get_auth_config(self) -> AuthConfig:
        """Get authentication configuration as dataclass"""
        return AuthConfig(**self._config.get('auth', {}))
    
    def get_ai_config(self) -> AIConfig:
        """Get AI configuration as dataclass"""
        return AIConfig(**self._config.get('ai', {}))
    
    def get_report_config(self) -> ReportConfig:
        """Get report configuration as dataclass"""
        return ReportConfig(**self._config.get('report', {}))
    
    def get_module_config(self) -> ModuleConfig:
        """Get module configuration as dataclass"""
        return ModuleConfig(**self._config.get('modules', {}))
    
    def get_all(self) -> Dict[str, Any]:
        """Get complete configuration dictionary"""
        return self._config.copy()
    
    def is_module_enabled(self, module_name: str) -> bool:
        """
        Check if a module is enabled
        
        Args:
            module_name: Name of the module
            
        Returns:
            True if module is enabled
        """
        return self._config.get('modules', {}).get(module_name, False)
    
    def get_wordlist_path(self, wordlist_type: str) -> Optional[str]:
        """
        Get path to wordlist file
        
        Args:
            wordlist_type: Type of wordlist (directories, files, payloads, etc.)
            
        Returns:
            Path to wordlist file or None
        """
        path = self._config.get('wordlists', {}).get(wordlist_type)
        if path:
            full_path = PROJECT_ROOT / path
            if full_path.exists():
                return str(full_path)
        return None


# Global configuration instance
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
config: Optional[ConfigManager] = None


def init_config(args=None) -> ConfigManager:
    """Initialize global configuration"""
    global config
    config = ConfigManager(args)
    return config


def get_config() -> ConfigManager:
    """Get global configuration instance"""
    if config is None:
        raise RuntimeError("Configuration not initialized")
    return config
