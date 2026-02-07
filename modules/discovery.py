#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path
import logging

from modules.base import BaseModule
from core.state import DiscoveredAsset, Finding

logger = logging.getLogger(__name__)


class DiscoveryModule(BaseModule):
    
    MODULE_NAME = "discovery"
    MODULE_DESCRIPTION = "Content discovery and endpoint enumeration"
    
    # Default wordlists
    DEFAULT_DIRS = [
        'admin', 'api', 'backup', 'config', 'css', 'data', 'db', 'docs',
        'files', 'images', 'includes', 'js', 'lib', 'logs', 'media',
        'private', 'public', 'resources', 'scripts', 'src', 'temp',
        'test', 'tmp', 'uploads', 'vendor', 'xml', 'json', 'api/v1',
        'api/v2', 'api/admin', 'administrator', 'login', 'register',
        'dashboard', 'panel', 'console', 'manage', 'management'
    ]
    
    DEFAULT_FILES = [
        'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
        'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
        'Dockerfile', 'docker-compose.yml', '.env', 'config.php',
        'config.xml', 'database.yml', 'backup.sql', 'dump.sql',
        '.git/HEAD', '.git/config', '.svn/entries', '.DS_Store',
        'crossdomain.xml', 'clientaccesspolicy.xml', 'phpinfo.php',
        'info.php', 'test.php', 'admin.php', 'login.php'
    ]
    
    DEFAULT_EXTENSIONS = ['', '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.json', '.xml']
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        super().__init__(config, state, http_client, ai_analyzer)
        self.target = config.get('target')
        self.parsed_url = urlparse(self.target)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Load wordlists
        self.dirs_wordlist = self._load_wordlist('directories', self.DEFAULT_DIRS)
        self.files_wordlist = self._load_wordlist('files', self.DEFAULT_FILES)
        
        # Discovered items
        self.discovered_paths: Set[str] = set()
        self.discovered_params: Dict[str, Set[str]] = {}
    
    def _load_wordlist(self, wordlist_type: str, defaults: List[str]) -> List[str]:

        wordlist_path = self.config.get_wordlist_path(wordlist_type)
        
        if wordlist_path and Path(wordlist_path).exists():
            try:
                with open(wordlist_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.logger.warning(f"Failed to load wordlist: {e}")
        
        return defaults
    
    async def run(self) -> Dict[str, Any]:
        
        self.logger.info(f"Starting content discovery for {self.base_url}")
        
        tasks = [
            self._discover_directories(),
            self._discover_files(),
            self._analyze_robots_txt(),
            self._discover_parameters(),
            self._enumerate_api_endpoints()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Discovery task failed: {result}")
            elif isinstance(result, dict):
                if 'assets' in result:
                    for asset_data in result['assets']:
                        asset = DiscoveredAsset(**asset_data)
                        self.state.add_asset(asset)
                if 'findings' in result:
                    for finding_data in result['findings']:
                        finding = Finding(**finding_data)
                        self.state.add_finding(finding)
        
        return self.get_results()
    
    async def _discover_directories(self) -> Dict[str, Any]:

        self.logger.info("Discovering directories")
        
        assets = []
        findings = []
        
        # Limit wordlist in silent mode
        mode = self.config.get('scan.mode')
        wordlist = self.dirs_wordlist[:20] if mode == 'silent' else self.dirs_wordlist
        
        # Create paths list
        paths_to_check = []
        for directory in wordlist:
            for ext in [''] if mode == 'silent' else self.DEFAULT_EXTENSIONS[:3]:
                path = f"/{directory}{ext}"
                paths_to_check.append(path)
        
        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(self.config.get('scan.threads', 10))
        
        async def bounded_check(path):
            async with semaphore:
                return await self._check_path(path)
        
        # Create tasks for each path
        tasks = [bounded_check(path) for path in paths_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.debug(f"Directory check failed: {result}")
                continue
                
            if isinstance(result, dict) and result.get('exists'):
                path = result['path']
                self.discovered_paths.add(path)
                
                assets.append({
                    'type': 'directory',
                    'value': urljoin(self.base_url, path),
                    'source': 'directory_bruteforce',
                    'metadata': {
                        'status_code': result.get('status_code'),
                        'content_length': result.get('content_length'),
                        'content_type': result.get('content_type')
                    }
                })
                
                # Check for sensitive directories
                sensitive_dirs = ['admin', 'backup', 'config', 'db', 'logs', 'private', 'test']
                if any(sd in path.lower() for sd in sensitive_dirs):
                    findings.append({
                        'id': 'DISC001',
                        'title': f'Sensitive Directory Exposed: {path}',
                        'description': f'A potentially sensitive directory was discovered: {path}',
                        'severity': 'medium',
                        'category': 'information_disclosure',
                        'url': urljoin(self.base_url, path),
                        'evidence': [f"Status: {result.get('status_code')}"],
                        'remediation': 'Restrict access to sensitive directories or remove them'
                    })
        
        return {'assets': assets, 'findings': findings}
    
    async def _discover_files(self) -> Dict[str, Any]:

        self.logger.info("Discovering sensitive files")
        
        assets = []
        findings = []
        
        # Limit in silent mode
        mode = self.config.get('scan.mode')
        wordlist = self.files_wordlist[:10] if mode == 'silent' else self.files_wordlist
        
        semaphore = asyncio.Semaphore(self.config.get('scan.threads', 10))
        
        async def bounded_check(path):
            async with semaphore:
                return await self._check_path(path)
        
        results = await asyncio.gather(
            *[bounded_check(f"/{f}") for f in wordlist],
            return_exceptions=True
        )
        
        for result in results:
            if isinstance(result, dict) and result.get('exists'):
                path = result['path']
                url = urljoin(self.base_url, path)
                
                assets.append({
                    'type': 'file',
                    'value': url,
                    'source': 'file_bruteforce',
                    'metadata': {
                        'status_code': result.get('status_code'),
                        'content_length': result.get('content_length'),
                        'content_type': result.get('content_type')
                    }
                })
                
                # Check for sensitive files
                sensitive_patterns = {
                    '.env': ('Environment File Exposed', 'critical'),
                    '.git/': ('Git Repository Exposed', 'critical'),
                    '.svn/': ('SVN Repository Exposed', 'high'),
                    'backup': ('Backup File Exposed', 'high'),
                    'config': ('Configuration File Exposed', 'high'),
                    'phpinfo': ('PHP Info Exposed', 'medium'),
                    '.sql': ('Database Dump Exposed', 'critical'),
                    'web.config': ('Web Config Exposed', 'medium'),
                    '.htaccess': ('HTAccess File Exposed', 'low')
                }
                
                for pattern, (title, severity) in sensitive_patterns.items():
                    if pattern in path.lower():
                        findings.append({
                            'id': 'FILE001',
                            'title': title,
                            'description': f'Sensitive file discovered: {path}',
                            'severity': severity,
                            'category': 'sensitive_file',
                            'url': url,
                            'evidence': [f"File: {path}", f"Status: {result.get('status_code')}"],
                            'remediation': f'Remove or restrict access to {path}'
                        })
                        break
        
        return {'assets': assets, 'findings': findings}
    
    async def _analyze_robots_txt(self) -> Dict[str, Any]:

        self.logger.info("Analyzing robots.txt")
        
        assets = []
        findings = []
        
        try:
            url = urljoin(self.base_url, '/robots.txt')
            response = await self.http_client.get(url)
            
            if response.status == 200:
                content = await response.text()
                
                # Parse robots.txt
                disallowed_paths = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                
                assets.append({
                    'type': 'robots_txt',
                    'value': url,
                    'source': 'robots_analysis',
                    'metadata': {
                        'disallowed_paths': disallowed_paths,
                        'content_preview': content[:500]
                    }
                })
                
                # Add disallowed paths as potential targets
                for path in disallowed_paths:
                    assets.append({
                        'type': 'hidden_path',
                        'value': urljoin(self.base_url, path),
                        'source': 'robots_txt',
                        'metadata': {'found_in': 'robots.txt'}
                    })
                
                # Check for sensitive paths in robots.txt
                sensitive_keywords = ['admin', 'backup', 'config', 'private', 'secret', 'internal']
                for path in disallowed_paths:
                    if any(sk in path.lower() for sk in sensitive_keywords):
                        findings.append({
                            'id': 'ROB001',
                            'title': 'Sensitive Path in robots.txt',
                            'description': f'robots.txt reveals sensitive path: {path}',
                            'severity': 'info',
                            'category': 'information_disclosure',
                            'url': url,
                            'evidence': [f"Disallow: {path}"],
                            'remediation': 'Consider removing sensitive paths from robots.txt'
                        })
        
        except Exception as e:
            self.logger.debug(f"robots.txt analysis failed: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    async def _discover_parameters(self) -> Dict[str, Any]:

        self.logger.info("Discovering parameters")
        
        assets = []
        
        # Common parameter names
        common_params = [
            'id', 'page', 'file', 'path', 'url', 'redirect', 'return',
            'callback', 'next', 'continue', 'target', 'dest', 'view',
            'action', 'cmd', 'exec', 'command', 'run', 'shell',
            'file', 'include', 'require', 'load', 'read', 'source'
        ]
        
        # Check discovered pages for parameters
        for path in list(self.discovered_paths)[:10]:  # Limit to first 10
            url = urljoin(self.base_url, path)
            
            try:
                # Test with common parameters
                for param in common_params[:5]:  # Limit in discovery phase
                    test_url = f"{url}?{param}=test"
                    response = await self.http_client.get(test_url)
                    
                    # If response differs from base, parameter might be valid
                    base_response = await self.http_client.get(url)
                    
                    base_text = await base_response.text()
                    test_text = await response.text()
                    
                    if len(base_text) != len(test_text):
                        assets.append({
                            'type': 'parameter',
                            'value': param,
                            'source': 'parameter_discovery',
                            'metadata': {
                                'url': url,
                                'response_diff': abs(len(base_text) - len(test_text))
                            }
                        })
            
            except Exception as e:
                self.logger.debug(f"Parameter discovery failed for {url}: {e}")
        
        return {'assets': assets, 'findings': []}
    
    async def _enumerate_api_endpoints(self) -> Dict[str, Any]:

        self.logger.info("Enumerating API endpoints")
        
        assets = []
        findings = []
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/graphql', '/swagger.json', '/api-docs',
            '/openapi.json', '/swagger-ui.html'
        ]
        
        # Skip in silent mode
        if self.config.get('scan.mode') == 'silent':
            return {'assets': [], 'findings': []}
        
        for path in api_paths:
            try:
                url = urljoin(self.base_url, path)
                response = await self.http_client.get(url)
                
                if response.status in [200, 401, 403]:
                    assets.append({
                        'type': 'api_endpoint',
                        'value': url,
                        'source': 'api_enumeration',
                        'metadata': {
                            'status_code': response.status,
                            'content_type': response.headers.get('Content-Type', 'unknown')
                        }
                    })
                    
                    # Check for exposed API documentation
                    if 'swagger' in path or 'api-docs' in path:
                        if response.status == 200:
                            findings.append({
                                'id': 'API001',
                                'title': 'Exposed API Documentation',
                                'description': f'API documentation is publicly accessible: {path}',
                                'severity': 'medium',
                                'category': 'api',
                                'url': url,
                                'evidence': [f"Status: {response.status}"],
                                'remediation': 'Restrict access to API documentation'
                            })
            
            except Exception as e:
                self.logger.debug(f"API enumeration failed for {path}: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    async def _check_path(self, path: str) -> Dict[str, Any]:

        try:
            url = urljoin(self.base_url, path)
            response = await self.http_client.get(url)
            
            # Consider path as existing if status is not 404
            exists = response.status not in [404, 410]
            
            return {
                'path': path,
                'exists': exists,
                'status_code': response.status,
                'content_length': len(await response.text()),
                'content_type': response.headers.get('Content-Type', 'unknown')
            }
        
        except Exception as e:
            self.logger.debug(f"Path check failed for {path}: {e}")
            return {'path': path, 'exists': False}
