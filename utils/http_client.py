#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Client Module

Advanced HTTP client with:
- Connection pooling
- Proxy support
- Custom headers
- Rate limiting
- Retry logic
"""

import asyncio
import aiohttp
import ssl
from typing import Dict, Optional, Any, Union
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


class HTTPClient:
    """
    Advanced asynchronous HTTP client
    
    Features:
    - Connection pooling
    - Automatic retries
    - Proxy support
    - Custom SSL handling
    - Request/Response interception
    """
    
    def __init__(self, config):
        """
        Initialize HTTP client
        
        Args:
            config: Configuration manager
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.connector: Optional[aiohttp.TCPConnector] = None
        
        # Statistics
        self.request_count = 0
        self.error_count = 0
        
        # Proxy
        self.proxy = config.get('proxy')
        
        # SSL context
        self.ssl_context = self._create_ssl_context()
        
        # Default headers
        self.default_headers = config.get('headers', {})
        
        # Timeout
        self.timeout = aiohttp.ClientTimeout(
            total=config.get('scan.timeout', 30)
        )
        
        logger.debug("HTTP client initialized")
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context based on configuration"""
        verify_ssl = self.config.get('scan.verify_ssl', False)
        
        if verify_ssl:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    async def initialize(self):
        """Initialize HTTP session"""
        # Create connector with connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            enable_cleanup_closed=True,
            force_close=False,
            ssl=self.ssl_context
        )
        
        # Create session
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=self.timeout,
            headers=self.default_headers,
            raise_for_status=False
        )
        
        logger.info("HTTP session initialized")
    
    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        """
        Make HTTP request
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            ClientResponse object
        """
        if not self.session:
            raise RuntimeError("HTTP session not initialized")
        
        # Prepare headers
        headers = kwargs.pop('headers', {})
        headers.update(self.default_headers)
        
        # Add authentication if configured
        auth_headers = self._get_auth_headers()
        headers.update(auth_headers)
        
        # Apply rate limiting if configured
        delay = self.config.get('scan.delay', 0)
        if delay > 0:
            await asyncio.sleep(delay)
        
        # Make request with retries
        retries = self.config.get('scan.retries', 3)
        last_error = None
        
        for attempt in range(retries):
            try:
                self.request_count += 1
                
                response = await self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    proxy=self.proxy,
                    ssl=self.ssl_context,
                    **kwargs
                )
                
                return response
                
            except asyncio.TimeoutError as e:
                last_error = e
                logger.warning(f"Request timeout (attempt {attempt + 1}/{retries}): {url}")
                
            except aiohttp.ClientError as e:
                last_error = e
                logger.warning(f"Request error (attempt {attempt + 1}/{retries}): {url} - {e}")
            
            # Wait before retry
            if attempt < retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # All retries failed
        self.error_count += 1
        raise last_error or Exception(f"Request failed after {retries} attempts")
    
    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make PUT request"""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make DELETE request"""
        return await self.request('DELETE', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make HEAD request"""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make OPTIONS request"""
        return await self.request('OPTIONS', url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make PATCH request"""
        return await self.request('PATCH', url, **kwargs)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        headers = {}
        
        auth_config = self.config.get('auth', {})
        if not auth_config.get('enabled'):
            return headers
        
        auth_type = auth_config.get('type', 'none')
        
        if auth_type == 'bearer':
            token = auth_config.get('header', '')
            if token.startswith('Bearer '):
                headers['Authorization'] = token
            else:
                headers['Authorization'] = f"Bearer {token}"
        
        elif auth_type == 'basic':
            import base64
            username = auth_config.get('username', '')
            password = auth_config.get('password', '')
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers['Authorization'] = f"Basic {credentials}"
        
        elif auth_type == 'cookie':
            cookie = auth_config.get('cookie', '')
            headers['Cookie'] = cookie
        
        return headers
    
    async def fetch_text(self, url: str, **kwargs) -> str:
        """
        Fetch URL and return text content
        
        Args:
            url: URL to fetch
            **kwargs: Additional request parameters
            
        Returns:
            Response text
        """
        response = await self.get(url, **kwargs)
        return await response.text()
    
    async def fetch_json(self, url: str, **kwargs) -> Any:
        """
        Fetch URL and return JSON content
        
        Args:
            url: URL to fetch
            **kwargs: Additional request parameters
            
        Returns:
            Parsed JSON
        """
        response = await self.get(url, **kwargs)
        return await response.json()
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            logger.info("HTTP session closed")
        
        if self.connector:
            await self.connector.close()
    
    def get_stats(self) -> Dict[str, int]:
        """Get request statistics"""
        return {
            'requests': self.request_count,
            'errors': self.error_count,
            'success_rate': (
                ((self.request_count - self.error_count) / self.request_count * 100)
                if self.request_count > 0 else 0
            )
        }
