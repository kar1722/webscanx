#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from .payload_generator import AIPayloadGenerator
from .injection_engine import AdaptiveInjectionEngine

from pathlib import Path
import logging

logger = logging.getLogger(__name__)



@dataclass
class CorrelationResult:

    finding_ids: List[str]
    correlation_type: str
    confidence: float
    description: str
    impact: str


class AIAnalyzer:
    
    def __init__(self, config):
        
        self.config = config
        self.enabled = config.get('ai.enabled', False)
        self.model = config.get('ai.model', 'default')
        self.confidence_threshold = config.get('ai.confidence_threshold', 0.7)
        self.learning_enabled = config.get('ai.learning_enabled', True)
        
        self.learned_patterns: List[Dict] = []
        self.false_positive_patterns: List[str] = []
        
        self.payload_generator = AIPayloadGenerator()
        self.injection_engine = None
        self.http_client = None  
        

        self._load_learned_data()
        
        logger.debug("AI analyzer initialized")
    
    async def initialize(self, http_client=None):
        """Initialize AI components"""
        if not self.enabled:
            logger.info("AI analysis is disabled")
            return
        
        logger.info("Initializing AI analysis engine")
        

        if http_client:
            self.http_client = http_client
        
        # In a real implementation, this would load ML models
        # For now, we use rule-based analysis
        self._initialize_rule_engine()
        

        if self.http_client:
            self.injection_engine = AdaptiveInjectionEngine(self.http_client, self.config)
        else:
            logger.warning("HTTP client not provided, injection engine will not be available")
    
    async def smart_attack(self, target_url, parameters, vulnerability_type):
        
        if not self.injection_engine:
            logger.error("Injection engine not initialized. Call initialize() first with http_client.")
            return []
        
        results = []
        
        for param, value in parameters.items():
            context = {
                'technology': self._detect_technology(target_url),
                'waf_detected': self._check_waf(target_url),
                'previous_attacks': self._get_attack_history(target_url, param)
            }
            
            injection_result = await self.injection_engine.test_injection(
                url=target_url,
                param=param,
                param_value=value,
                vulnerability_type=vulnerability_type,
                context=context
            )
            
            if injection_result['vulnerable']:
                results.append(injection_result)
        
        return results
    
    def _detect_technology(self, url):

        # يمكن تطوير هذه الدالة لاحقاً لتحليل حقيقي
        return "unknown"
    
    def _check_waf(self, url):

        # يمكن تطوير هذه الدالة لاحقاً
        return False
    
    def _get_attack_history(self, url, param):

        return []

    def _initialize_rule_engine(self):

        self.correlation_rules = [
            {
                'name': 'SQLi + Information Disclosure',
                'description': 'SQL injection combined with information disclosure increases risk',
                'finding_types': ['sqli', 'information_disclosure'],
                'impact': 'Critical - Attackers can extract sensitive data',
                'confidence': 0.9
            },
            {
                'name': 'XSS + Missing CSP',
                'description': 'XSS vulnerability without Content Security Policy',
                'finding_types': ['xss', 'security_headers'],
                'conditions': {
                    'security_headers': lambda f: 'CSP' in f.get('title', '') or 'Content Security' in f.get('title', '')
                },
                'impact': 'High - XSS attacks are easier to execute',
                'confidence': 0.85
            },
            {
                'name': 'RCE + Backup Files',
                'description': 'Remote code execution with exposed backup files',
                'finding_types': ['rce', 'sensitive_file'],
                'conditions': {
                    'sensitive_file': lambda f: 'backup' in f.get('title', '').lower()
                },
                'impact': 'Critical - Full system compromise possible',
                'confidence': 0.95
            },
            {
                'name': 'LFI + PHP Info',
                'description': 'Local file inclusion with exposed PHP info',
                'finding_types': ['lfi', 'sensitive_file'],
                'conditions': {
                    'sensitive_file': lambda f: 'phpinfo' in f.get('title', '').lower()
                },
                'impact': 'High - Easier to exploit LFI',
                'confidence': 0.8
            },
            {
                'name': 'Weak Auth + IDOR',
                'description': 'Weak authentication with insecure direct object references',
                'finding_types': ['idor'],
                'impact': 'High - Unauthorized data access',
                'confidence': 0.85
            }
        ]
        
        self.pattern_rules = [
            {
                'name': 'Technology Stack Vulnerabilities',
                'description': 'Multiple vulnerabilities in same technology',
                'pattern': 'technology_concentration',
                'detector': self._detect_tech_concentration
            },
            {
                'name': 'Defense in Depth Failure',
                'description': 'Multiple security controls failing',
                'pattern': 'defense_failure',
                'detector': self._detect_defense_failure
            },
            {
                'name': 'Attack Chain Potential',
                'description': 'Vulnerabilities that can be chained',
                'pattern': 'attack_chain',
                'detector': self._detect_attack_chain
            }
        ]
    
    async def analyze_findings(self, findings: List[Any]) -> Dict[str, Any]:
        
        if not self.enabled:
            return {'status': 'disabled'}
        
        logger.info(f"Analyzing {len(findings)} findings with AI")
        
        analysis = {
            'total_findings': len(findings),
            'severity_distribution': self._analyze_severity(findings),
            'category_distribution': self._analyze_categories(findings),
            'risk_assessment': await self._assess_risk(findings),
            'prioritized_findings': self._prioritize_findings(findings),
            'false_positive_probability': self._estimate_false_positives(findings)
        }
        
        return analysis
    
    async def correlate_findings(self, findings: List[Any], assets: List[Any]) -> List[CorrelationResult]:
       
        if not self.enabled:
            return []
        
        logger.info("Correlating findings")
        
        correlations = []
        

        for rule in self.correlation_rules:
            matches = self._apply_correlation_rule(rule, findings)
            correlations.extend(matches)
        

        for rule in self.pattern_rules:
            pattern_matches = rule['detector'](findings, assets)
            correlations.extend(pattern_matches)
        

        correlations.sort(key=lambda x: x.confidence, reverse=True)
        
        return correlations
    
    async def generate_insights(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
       
        if not self.enabled:
            return []
        
        logger.info("Generating AI insights")
        
        insights = []
        
        posture = self._assess_security_posture(scan_data)
        insights.append({
            'type': 'security_posture',
            'title': 'Security Posture Assessment',
            'description': posture['description'],
            'risk_level': posture['risk_level'],
            'confidence': posture['confidence']
        })
        
        attack_surface = self._analyze_attack_surface(scan_data)
        insights.append({
            'type': 'attack_surface',
            'title': 'Attack Surface Analysis',
            'description': attack_surface['description'],
            'key_findings': attack_surface['findings'],
            'confidence': attack_surface['confidence']
        })
        
        remediation = self._prioritize_remediation(scan_data)
        insights.append({
            'type': 'remediation',
            'title': 'Remediation Priority',
            'description': remediation['description'],
            'priority_order': remediation['priority'],
            'confidence': remediation['confidence']
        })
        
        return insights
    
    def _apply_correlation_rule(self, rule: Dict, findings: List[Any]) -> List[CorrelationResult]:

        correlations = []
        

        matching_findings = []
        for finding in findings:
            if finding.category.lower() in rule['finding_types']:

                conditions = rule.get('conditions', {})
                if finding.category.lower() in conditions:
                    if not conditions[finding.category.lower()](finding.to_dict()):
                        continue
                matching_findings.append(finding)
        

        if len(matching_findings) >= len(rule['finding_types']):

            url_groups = {}
            for f in matching_findings:
                url = getattr(f, 'url', '')
                if url not in url_groups:
                    url_groups[url] = []
                url_groups[url].append(f)
            
            for url, group in url_groups.items():
                categories = set(f.category.lower() for f in group)
                if len(categories) >= len(rule['finding_types']):
                    correlations.append(CorrelationResult(
                        finding_ids=[f.id for f in group],
                        correlation_type=rule['name'],
                        confidence=rule['confidence'],
                        description=rule['description'],
                        impact=rule['impact']
                    ))
        
        return correlations
    
    def _detect_tech_concentration(self, findings: List[Any], assets: List[Any]) -> List[CorrelationResult]:

        correlations = []
        
        # Group findings by technology
        tech_findings = {}
        for finding in findings:
            tech = finding.metadata.get('technology', 'unknown')
            if tech not in tech_findings:
                tech_findings[tech] = []
            tech_findings[tech].append(finding)
        
        # Find technologies with multiple vulnerabilities
        for tech, tech_finds in tech_findings.items():
            if len(tech_finds) >= 3:
                correlations.append(CorrelationResult(
                    finding_ids=[f.id for f in tech_finds],
                    correlation_type='Technology Concentration',
                    confidence=0.8,
                    description=f'Multiple vulnerabilities found in {tech}',
                    impact=f'{tech} has significant security weaknesses'
                ))
        
        return correlations
    
    def _detect_defense_failure(self, findings: List[Any], assets: List[Any]) -> List[CorrelationResult]:

        correlations = []
        
        # Count security control failures
        control_failures = {
            'authentication': 0,
            'authorization': 0,
            'input_validation': 0,
            'output_encoding': 0,
            'logging': 0
        }
        
        category_mapping = {
            'sqli': 'input_validation',
            'xss': 'output_encoding',
            'idor': 'authorization',
            'auth': 'authentication',
            'rce': 'input_validation',
            'lfi': 'input_validation',
            'info': 'logging'
        }
        
        for finding in findings:
            control = category_mapping.get(finding.category.lower(), 'other')
            if control in control_failures:
                control_failures[control] += 1
        
        # Check for multiple control failures
        failed_controls = [c for c, count in control_failures.items() if count > 0]
        if len(failed_controls) >= 3:
            correlations.append(CorrelationResult(
                finding_ids=[f.id for f in findings],
                correlation_type='Defense in Depth Failure',
                confidence=0.85,
                description=f'Multiple security controls failing: {", ".join(failed_controls)}',
                impact='System has inadequate defense in depth'
            ))
        
        return correlations
    
    def _detect_attack_chain(self, findings: List[Any], assets: List[Any]) -> List[CorrelationResult]:
        """Detect potential attack chains"""
        correlations = []
        
        # Define attack chains
        attack_chains = [
            ['info', 'sqli', 'rce'],
            ['info', 'lfi', 'rce'],
            ['xss', 'session', 'idor'],
            ['redirect', 'xss', 'session']
        ]
        
        finding_categories = [f.category.lower() for f in findings]
        
        for chain in attack_chains:
            if all(step in finding_categories for step in chain):
                chain_findings = [f for f in findings if f.category.lower() in chain]
                correlations.append(CorrelationResult(
                    finding_ids=[f.id for f in chain_findings],
                    correlation_type='Attack Chain Detected',
                    confidence=0.75,
                    description=f'Potential attack chain: {" -> ".join(chain)}',
                    impact='Attackers may chain vulnerabilities for greater impact'
                ))
        
        return correlations
    
    def _analyze_severity(self, findings: List[Any]) -> Dict[str, int]:

        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = getattr(finding, 'severity', 'info').lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _analyze_categories(self, findings: List[Any]) -> Dict[str, int]:

        distribution = {}
        
        for finding in findings:
            category = getattr(finding, 'category', 'unknown').lower()
            distribution[category] = distribution.get(category, 0) + 1
        
        return distribution
    
    async def _assess_risk(self, findings: List[Any]) -> Dict[str, Any]:

        severity_dist = self._analyze_severity(findings)
        
        # Calculate risk score
        risk_score = (
            severity_dist['critical'] * 10 +
            severity_dist['high'] * 5 +
            severity_dist['medium'] * 2 +
            severity_dist['low'] * 0.5
        )
        
        # Determine risk level
        if risk_score >= 20:
            risk_level = 'critical'
        elif risk_score >= 10:
            risk_level = 'high'
        elif risk_score >= 5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'score': risk_score,
            'level': risk_level,
            'description': f'Overall risk level is {risk_level} with score {risk_score}'
        }
    
    def _prioritize_findings(self, findings: List[Any]) -> List[Dict[str, Any]]:

        prioritized = []
        
        for finding in findings:
            # Calculate priority score
            severity_scores = {
                'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1
            }
            base_score = severity_scores.get(finding.severity.lower(), 1)
            
            # Adjust based on confidence
            confidence = getattr(finding, 'confidence', 1.0)
            adjusted_score = base_score * confidence
            
            # Adjust based on exploitability
            easily_exploitable = ['sqli', 'xss', 'rce', 'lfi', 'idor']
            if finding.category.lower() in easily_exploitable:
                adjusted_score *= 1.2
            
            prioritized.append({
                'id': finding.id,
                'title': finding.title,
                'priority_score': adjusted_score,
                'severity': finding.severity,
                'category': finding.category
            })
        
        # Sort by priority score
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return prioritized
    
    def _estimate_false_positives(self, findings: List[Any]) -> Dict[str, Any]:

        fp_indicators = {
            'low_confidence': 0.3,
            'generic_error': 0.2,
            'outdated_signature': 0.25
        }
        
        estimates = {}
        
        for finding in findings:
            fp_probability = 0.0
            
            # Low confidence increases FP probability
            if getattr(finding, 'confidence', 1.0) < 0.7:
                fp_probability += fp_indicators['low_confidence']
            
            # Check against learned false positive patterns
            for pattern in self.false_positive_patterns:
                if pattern in finding.title.lower() or pattern in finding.description.lower():
                    fp_probability += 0.2
            
            estimates[finding.id] = {
                'probability': min(fp_probability, 0.95),
                'likely_false_positive': fp_probability > 0.5
            }
        
        return estimates
    
    def _assess_security_posture(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:

        findings = scan_data.get('findings', [])
        
        if not findings:
            return {
                'description': 'No vulnerabilities detected. Security posture appears strong.',
                'risk_level': 'low',
                'confidence': 0.7
            }
        
        severity_dist = self._analyze_severity(findings)
        
        if severity_dist['critical'] > 0:
            return {
                'description': f'Critical security issues detected ({severity_dist["critical"]} critical). Immediate attention required.',
                'risk_level': 'critical',
                'confidence': 0.9
            }
        elif severity_dist['high'] > 2:
            return {
                'description': f'Multiple high-severity vulnerabilities ({severity_dist["high"]} high). Significant security weaknesses.',
                'risk_level': 'high',
                'confidence': 0.85
            }
        elif severity_dist['high'] > 0 or severity_dist['medium'] > 3:
            return {
                'description': 'Moderate security issues present. Review and remediation recommended.',
                'risk_level': 'medium',
                'confidence': 0.8
            }
        else:
            return {
                'description': 'Minor security issues detected. Overall posture is acceptable but can be improved.',
                'risk_level': 'low',
                'confidence': 0.75
            }
    
    def _analyze_attack_surface(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:

        summary = scan_data.get('summary', {})
        
        endpoints = summary.get('endpoints_discovered', 0)
        params = summary.get('parameters_found', 0)
        tech = summary.get('technologies_detected', 0)
        
        description = f"""
        Attack Surface Summary:
        - {endpoints} endpoints discovered
        - {params} parameters identified
        - {tech} technologies detected
        
        The application's attack surface is {'large' if endpoints > 50 else 'moderate' if endpoints > 20 else 'small'}.
        {'High number of parameters increases injection attack risk.' if params > 100 else ''}
        {'Multiple technologies increase complexity and potential vulnerabilities.' if tech > 5 else ''}
        """
        
        return {
            'description': description,
            'findings': [
                f'{endpoints} endpoints',
                f'{params} parameters',
                f'{tech} technologies'
            ],
            'confidence': 0.8
        }
    
    def _prioritize_remediation(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:

        findings = scan_data.get('findings', [])
        
        if not findings:
            return {
                'description': 'No remediation needed.',
                'priority': [],
                'confidence': 1.0
            }
        
        # Group by category
        by_category = {}
        for finding in findings:
            cat = finding.category.lower()
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(finding)
        
        # Priority order based on impact
        priority_categories = ['rce', 'sqli', 'xss', 'lfi', 'idor', 'auth', 'config']
        
        priority = []
        for cat in priority_categories:
            if cat in by_category:
                count = len(by_category[cat])
                priority.append(f'{cat.upper()}: {count} issues')
        
        description = f"""
        Remediation Priority:
        1. Address critical and high severity issues first
        2. Focus on injection vulnerabilities (SQLi, RCE, XSS)
        3. Fix authentication and authorization issues
        4. Address information disclosure
        5. Implement security headers
        """
        
        return {
            'description': description,
            'priority': priority,
            'confidence': 0.85
        }
    
    def _load_learned_data(self):

        learn_file = Path('ai_learning.json')
        if learn_file.exists():
            try:
                with open(learn_file, 'r') as f:
                    data = json.load(f)
                    self.learned_patterns = data.get('patterns', [])
                    self.false_positive_patterns = data.get('false_positives', [])
            except Exception as e:
                logger.debug(f"Failed to load learned data: {e}")
    
    def _save_learned_data(self):

        if not self.learning_enabled:
            return
        
        try:
            with open('ai_learning.json', 'w') as f:
                json.dump({
                    'patterns': self.learned_patterns,
                    'false_positives': self.false_positive_patterns
                }, f)
        except Exception as e:
            logger.debug(f"Failed to save learned data: {e}")
    
    async def cleanup(self):

        self._save_learned_data()
        logger.info("AI analyzer cleanup complete")
