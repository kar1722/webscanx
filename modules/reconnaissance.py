#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import socket
import ssl
import json
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
import logging

from modules.base import BaseModule
from core.state import DiscoveredAsset, Finding

logger = logging.getLogger(__name__)


class ReconnaissanceModule(BaseModule):
    
    MODULE_NAME = "reconnaissance"
    MODULE_DESCRIPTION = "Initial reconnaissance and information gathering"
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        super().__init__(config, state, http_client, ai_analyzer)
        self.target = config.get('target')
        self.parsed_url = urlparse(self.target)
        self.domain = self.parsed_url.hostname
        
    async def initialize(self):

        self.logger.info(f"Initializing reconnaissance for {self.domain}")
    
    async def run(self) -> Dict[str, Any]:
     
        self.logger.info(f"Starting reconnaissance for {self.domain}")
        
        tasks = [
            self._gather_dns_info(),
            self._analyze_ssl_cert(),
            self._fingerprint_technology(),
            self._gather_server_info(),
            self._discover_subdomains(),
            self._analyze_headers()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Reconnaissance task failed: {result}")
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
    
    async def _gather_dns_info(self) -> Dict[str, Any]:

        self.logger.info("Gathering DNS information")
        
        assets = []
        findings = []
        
        try:
            # Get IP address
            ip = socket.gethostbyname(self.domain)
            assets.append({
                'type': 'ip_address',
                'value': ip,
                'source': 'dns_resolution',
                'metadata': {'domain': self.domain}
            })
            
            # Try to get all IP addresses
            try:
                addr_info = socket.getaddrinfo(self.domain, None)
                ips = set()
                for info in addr_info:
                    ips.add(info[4][0])
                
                for ip in ips:
                    assets.append({
                        'type': 'ip_address',
                        'value': ip,
                        'source': 'dns_resolution',
                        'metadata': {'domain': self.domain, 'family': 'IPv6' if ':' in ip else 'IPv4'}
                    })
            except Exception as e:
                self.logger.debug(f"IPv6 resolution failed: {e}")
            
            # Check for MX records
            try:
                mx_records = await self._query_mx(self.domain)
                for mx in mx_records:
                    assets.append({
                        'type': 'mx_record',
                        'value': mx,
                        'source': 'dns_query',
                        'metadata': {'domain': self.domain}
                    })
            except Exception as e:
                self.logger.debug(f"MX query failed: {e}")
            
            # Check for TXT records (SPF, DKIM, DMARC)
            try:
                txt_records = await self._query_txt(self.domain)
                for txt in txt_records:
                    assets.append({
                        'type': 'txt_record',
                        'value': txt,
                        'source': 'dns_query',
                        'metadata': {'domain': self.domain}
                    })
                    
                    # Check for security issues
                    if 'v=spf1' in txt:
                        if '+all' in txt or '~all' not in txt:
                            findings.append({
                                'id': 'DNS001',
                                'title': 'Weak SPF Record Configuration',
                                'description': f'SPF record allows all senders: {txt}',
                                'severity': 'medium',
                                'category': 'dns',
                                'url': self.target,
                                'evidence': [txt],
                                'remediation': 'Configure SPF record with strict policy (-all)'
                            })
            except Exception as e:
                self.logger.debug(f"TXT query failed: {e}")
            
        except Exception as e:
            self.logger.error(f"DNS info gathering failed: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    async def _analyze_ssl_cert(self) -> Dict[str, Any]:

        if self.parsed_url.scheme != 'https':
            return {'assets': [], 'findings': []}
        
        self.logger.info("Analyzing SSL certificate")
        
        assets = []
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Add SSL info as asset
                    assets.append({
                        'type': 'ssl_info',
                        'value': f"{self.domain}:443",
                        'source': 'ssl_analysis',
                        'metadata': {
                            'subject': cert.get('subject'),
                            'issuer': cert.get('issuer'),
                            'not_after': cert.get('notAfter'),
                            'not_before': cert.get('notBefore'),
                            'serial_number': cert.get('serialNumber'),
                            'cipher': cipher,
                            'tls_version': version
                        }
                    })
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        findings.append({
                            'id': 'SSL001',
                            'title': 'Outdated TLS Version',
                            'description': f'Server supports deprecated {version}',
                            'severity': 'high',
                            'category': 'ssl',
                            'url': self.target,
                            'evidence': [f"TLS Version: {version}"],
                            'remediation': 'Disable TLS 1.0 and 1.1, enable TLS 1.2 or higher'
                        })
                    
                    # Check certificate expiration
                    from datetime import datetime
                    
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            findings.append({
                                'id': 'SSL002',
                                'title': 'Expired SSL Certificate',
                                'description': f'SSL certificate expired {abs(days_until_expiry)} days ago',
                                'severity': 'critical',
                                'category': 'ssl',
                                'url': self.target,
                                'evidence': [f"Expiry Date: {not_after}"],
                                'remediation': 'Renew SSL certificate immediately'
                            })
                        elif days_until_expiry < 30:
                            findings.append({
                                'id': 'SSL003',
                                'title': 'SSL Certificate Expiring Soon',
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'severity': 'medium',
                                'category': 'ssl',
                                'url': self.target,
                                'evidence': [f"Expiry Date: {not_after}"],
                                'remediation': 'Renew SSL certificate before expiration'
                            })
                    
                    # Check for weak cipher
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                        if any(wc in cipher_name for wc in weak_ciphers):
                            findings.append({
                                'id': 'SSL004',
                                'title': 'Weak SSL Cipher',
                                'description': f'Server uses weak cipher: {cipher_name}',
                                'severity': 'high',
                                'category': 'ssl',
                                'url': self.target,
                                'evidence': [f"Cipher: {cipher_name}"],
                                'remediation': 'Disable weak ciphers, use only strong ciphers'
                            })
        
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    async def _fingerprint_technology(self) -> Dict[str, Any]:

        self.logger.info("Fingerprinting technologies")
        
        assets = []
        
        try:
            response = await self.http_client.get(self.target)
            self.state.increment_requests(success=True)
            headers = dict(response.headers)
            
            # Analyze headers for technology detection
            tech_signatures = {
                'Server': {
                    'Apache': 'Apache HTTP Server',
                    'nginx': 'Nginx',
                    'IIS': 'Microsoft IIS',
                    'cloudflare': 'Cloudflare'
                },
                'X-Powered-By': {
                    'PHP': 'PHP',
                    'ASP.NET': 'ASP.NET',
                    'Express': 'Express.js'
                },
                'X-Generator': {
                    'Drupal': 'Drupal CMS',
                    'WordPress': 'WordPress CMS'
                }
            }
            
            for header, signatures in tech_signatures.items():
                header_value = headers.get(header, '')
                for signature, tech_name in signatures.items():
                    if signature.lower() in header_value.lower():
                        assets.append({
                            'type': 'technology',
                            'value': tech_name,
                            'source': 'header_fingerprinting',
                            'confidence': 0.9,
                            'metadata': {
                                'header': header,
                                'value': header_value
                            }
                        })
            
            # Detect framework from cookies
            cookies = response.cookies
            cookie_signatures = {
                'PHPSESSID': 'PHP',
                'sessionid': 'Django',
                'asp.net_sessionid': 'ASP.NET',
                'JSESSIONID': 'Java EE'
            }
            
            for cookie in cookies.values():
                for signature, tech in cookie_signatures.items():
                    if signature.lower() in cookie.key.lower():
                        assets.append({
                            'type': 'technology',
                            'value': tech,
                            'source': 'cookie_fingerprinting',
                            'confidence': 0.8,
                            'metadata': {'cookie': cookie.key}
                        })
            
            # Store headers in state
            self.state.headers = headers
            
        except Exception as e:
            self.logger.error(f"Technology fingerprinting failed: {e}")
            self.state.increment_requests(success=False)
        
        return {'assets': assets, 'findings': []}
    
    async def _gather_server_info(self) -> Dict[str, Any]:

        self.logger.info("Gathering server information")
        
        assets = []
        findings = []
        
        try:
            # Make request and analyze response
            response = await self.http_client.get(self.target)
            self.state.increment_requests(success=True)
            
            # Check for information disclosure
            headers = dict(response.headers)
            
            # Server header disclosure
            server_header = headers.get('Server', '')
            if server_header and server_header != '':
                if '/' in server_header:  # Version disclosure
                    findings.append({
                        'id': 'INFO001',
                        'title': 'Server Version Disclosure',
                        'description': f'Server header reveals version: {server_header}',
                        'severity': 'low',
                        'category': 'information_disclosure',
                        'url': self.target,
                        'evidence': [f"Server: {server_header}"],
                        'remediation': 'Configure server to hide version information'
                    })
            
            # X-Powered-By disclosure
            x_powered = headers.get('X-Powered-By', '')
            if x_powered:
                findings.append({
                    'id': 'INFO002',
                    'title': 'Technology Stack Disclosure',
                    'description': f'X-Powered-By header reveals technology: {x_powered}',
                    'severity': 'info',
                    'category': 'information_disclosure',
                    'url': self.target,
                    'evidence': [f"X-Powered-By: {x_powered}"],
                    'remediation': 'Remove X-Powered-By header from responses'
                })
            
            # Add server info as asset
            assets.append({
                'type': 'server_info',
                'value': self.target,
                'source': 'http_analysis',
                'metadata': {
                    'status_code': response.status,
                    'headers': dict(headers),
                    'content_type': headers.get('Content-Type', 'unknown')
                }
            })
            
        except Exception as e:
            self.logger.error(f"Server info gathering failed: {e}")
            self.state.increment_requests(success=False)
        
        return {'assets': assets, 'findings': findings}
    
    async def _discover_subdomains(self) -> Dict[str, Any]:

        self.logger.info("Discovering subdomains")
        
        assets = []
        
        # Skip in silent mode
        if self.config.get('scan.mode') == 'silent':
            return {'assets': [], 'findings': []}
        
        try:
            # Common subdomains to check
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api',
                'dev', 'test', 'staging', 'portal', 'secure', 'vpn',
                'remote', 'webmail', 'support', 'help', 'docs'
            ]
            
            # Check each subdomain
            tasks = []
            for sub in common_subdomains:
                subdomain = f"{sub}.{self.domain}"
                tasks.append(self._check_subdomain(subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('exists'):
                    assets.append({
                        'type': 'subdomain',
                        'value': result['subdomain'],
                        'source': 'subdomain_enumeration',
                        'metadata': {
                            'ip': result.get('ip'),
                            'methods': result.get('methods', [])
                        }
                    })
        
        except Exception as e:
            self.logger.error(f"Subdomain discovery failed: {e}")
        
        return {'assets': assets, 'findings': []}
    
    async def _check_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Check if subdomain exists"""
        try:
            # Try DNS resolution
            ip = socket.gethostbyname(subdomain)
            return {
                'subdomain': subdomain,
                'exists': True,
                'ip': ip,
                'methods': ['dns']
            }
        except socket.gaierror:
            return {'subdomain': subdomain, 'exists': False}
        except Exception as e:
            self.logger.debug(f"Subdomain check failed for {subdomain}: {e}")
            return {'subdomain': subdomain, 'exists': False}
    
    async def _analyze_headers(self) -> Dict[str, Any]:

        self.logger.info("Analyzing security headers")
        
        findings = []
        
        try:
            response = await self.http_client.get(self.target)
            self.state.increment_requests(success=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Security headers to check
            security_headers = {
                'strict-transport-security': {
                    'name': 'HSTS',
                    'severity': 'medium',
                    'description': 'HTTP Strict Transport Security header is missing'
                },
                'content-security-policy': {
                    'name': 'CSP',
                    'severity': 'medium',
                    'description': 'Content Security Policy header is missing'
                },
                'x-frame-options': {
                    'name': 'X-Frame-Options',
                    'severity': 'medium',
                    'description': 'X-Frame-Options header is missing (clickjacking protection)'
                },
                'x-content-type-options': {
                    'name': 'X-Content-Type-Options',
                    'severity': 'low',
                    'description': 'X-Content-Type-Options header is missing (MIME sniffing protection)'
                },
                'x-xss-protection': {
                    'name': 'X-XSS-Protection',
                    'severity': 'low',
                    'description': 'X-XSS-Protection header is missing'
                },
                'referrer-policy': {
                    'name': 'Referrer-Policy',
                    'severity': 'low',
                    'description': 'Referrer-Policy header is missing'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    findings.append({
                        'id': f'HEAD{list(security_headers.keys()).index(header) + 1:03d}',
                        'title': f"Missing {info['name']} Header",
                        'description': info['description'],
                        'severity': info['severity'],
                        'category': 'security_headers',
                        'url': self.target,
                        'evidence': [f"Header not found: {header}"],
                        'remediation': f"Add {info['name']} header to all responses"
                    })
            
            # Check HSTS for HTTPS sites
            if self.parsed_url.scheme == 'https':
                hsts = headers.get('strict-transport-security', '')
                if not hsts or 'max-age' not in hsts:
                    findings.append({
                        'id': 'HEAD001',
                        'title': 'HSTS Header Missing or Invalid',
                        'description': 'HSTS header is missing or does not contain max-age directive',
                        'severity': 'medium',
                        'category': 'security_headers',
                        'url': self.target,
                        'evidence': [f"HSTS: {hsts}"],
                        'remediation': 'Add Strict-Transport-Security header with appropriate max-age'
                    })
        
        except Exception as e:
            self.logger.error(f"Header analysis failed: {e}")
            self.state.increment_requests(success=False)
        
        return {'assets': [], 'findings': findings}
    
    async def _query_mx(self, domain: str) -> List[str]:
        # Simplified MX query
        return []
    
    async def _query_txt(self, domain: str) -> List[str]:
        # Simplified TXT query
        return []
