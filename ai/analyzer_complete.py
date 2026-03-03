#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced AI Analyzer with Advanced Correlation and Learning
"""

import json
import re
import pickle
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Correlation between multiple findings"""
    finding_ids: List[str]
    correlation_type: str
    confidence: float
    description: str
    impact: str
    attack_chain: Optional[List[str]] = None
    remediation_priority: str = "high"


@dataclass
class LearnedPattern:
    """Pattern learned from previous scans"""
    pattern_type: str
    indicators: List[str]
    confidence: float
    false_positive_rate: float
    occurrences: int
    last_seen: str


class EnhancedAIAnalyzer:
    """Advanced AI analyzer with correlation and learning"""
    
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('ai.enabled', False)
        self.learning_enabled = config.get('ai.learning_enabled', True)
        self.confidence_threshold = config.get('ai.confidence_threshold', 0.7)
        
        # Learning data
        self.learned_patterns: List[LearnedPattern] = []
        self.false_positive_signatures: List[Dict] = []
        self.vulnerability_patterns: Dict[str, List[Dict]] = defaultdict(list)
        
        # Statistics
        self.scan_history: List[Dict] = []
        self.accuracy_metrics: Dict[str, float] = {}
        
        # Data persistence
        self.data_dir = Path.home() / '.webscanx' / 'ai_data'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self._load_learned_data()
        self._initialize_correlation_rules()
    
    def _load_learned_data(self):
        """Load previously learned patterns"""
        try:
            patterns_file = self.data_dir / 'learned_patterns.json'
            if patterns_file.exists():
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    self.learned_patterns = [LearnedPattern(**p) for p in data.get('patterns', [])]
                    self.false_positive_signatures = data.get('false_positives', [])
                    self.vulnerability_patterns = defaultdict(list, data.get('vuln_patterns', {}))
                logger.info(f"Loaded {len(self.learned_patterns)} learned patterns")
        except Exception as e:
            logger.warning(f"Could not load learned data: {e}")
    
    def _save_learned_data(self):
        """Save learned patterns for future scans"""
        if not self.learning_enabled:
            return
        
        try:
            patterns_file = self.data_dir / 'learned_patterns.json'
            data = {
                'patterns': [asdict(p) for p in self.learned_patterns],
                'false_positives': self.false_positive_signatures,
                'vuln_patterns': dict(self.vulnerability_patterns)
            }
            with open(patterns_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved learned patterns")
        except Exception as e:
            logger.error(f"Could not save learned data: {e}")
    
    def _initialize_correlation_rules(self):
        """Initialize correlation detection rules"""
        self.correlation_rules = [
            {
                'name': 'SQLi + Information Disclosure',
                'types': ['sqli', 'information_disclosure'],
                'impact': 'Critical - Database compromise with data exfiltration',
                'confidence': 0.95,
                'attack_chain': ['Enumerate database', 'Extract credentials', 'Escalate privileges']
            },
            {
                'name': 'XSS + Missing CSP',
                'types': ['xss', 'missing_csp'],
                'impact': 'High - XSS exploitation without mitigation',
                'confidence': 0.9,
                'attack_chain': ['Inject malicious script', 'Steal session tokens', 'Account takeover']
            },
            {
                'name': 'RCE + Weak Authentication',
                'types': ['rce', 'weak_auth'],
                'impact': 'Critical - Full system compromise',
                'confidence': 0.98,
                'attack_chain': ['Bypass authentication', 'Execute arbitrary code', 'Establish persistence']
            },
            {
                'name': 'LFI + Sensitive Files',
                'types': ['lfi', 'sensitive_file'],
                'impact': 'High - Configuration and credential exposure',
                'confidence': 0.85,
                'attack_chain': ['Read sensitive files', 'Extract credentials', 'Lateral movement']
            },
            {
                'name': 'SSRF + Cloud Metadata',
                'types': ['ssrf', 'cloud_metadata'],
                'impact': 'Critical - Cloud infrastructure compromise',
                'confidence': 0.92,
                'attack_chain': ['Access metadata service', 'Steal IAM credentials', 'Compromise cloud resources']
            },
            {
                'name': 'XXE + External Entities',
                'types': ['xxe', 'xml_parsing'],
                'impact': 'High - Data exfiltration and SSRF',
                'confidence': 0.88,
                'attack_chain': ['Inject external entity', 'Read local files', 'Exfiltrate data']
            },
            {
                'name': 'IDOR + Missing Authorization',
                'types': ['idor', 'missing_authz'],
                'impact': 'High - Unauthorized data access',
                'confidence': 0.87,
                'attack_chain': ['Enumerate resources', 'Access unauthorized data', 'Modify sensitive records']
            },
            {
                'name': 'CSRF + Missing Token',
                'types': ['csrf', 'missing_csrf_token'],
                'impact': 'Medium - State-changing operations without consent',
                'confidence': 0.8,
                'attack_chain': ['Craft malicious request', 'Trick user interaction', 'Execute unauthorized action']
            },
            {
                'name': 'Open Redirect + OAuth',
                'types': ['open_redirect', 'oauth'],
                'impact': 'High - OAuth token theft',
                'confidence': 0.83,
                'attack_chain': ['Manipulate redirect', 'Intercept OAuth flow', 'Steal access tokens']
            },
            {
                'name': 'Subdomain Takeover + Session Cookies',
                'types': ['subdomain_takeover', 'insecure_cookies'],
                'impact': 'Critical - Session hijacking via subdomain',
                'confidence': 0.91,
                'attack_chain': ['Take over subdomain', 'Set malicious cookies', 'Hijack user sessions']
            }
        ]
    
    async def analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive AI-powered analysis of scan results"""
        
        if not self.enabled:
            return {'status': 'disabled', 'message': 'AI analysis is disabled'}
        
        findings = results.get('vulnerabilities', [])
        logger.info(f"AI analyzing {len(findings)} findings")
        
        analysis = {
            'total_findings': len(findings),
            'correlations': await self._find_correlations(findings),
            'attack_chains': self._identify_attack_chains(findings),
            'risk_score': self._calculate_risk_score(findings),
            'false_positives': self._detect_false_positives(findings),
            'prioritized_findings': self._prioritize_findings(findings),
            'technology_risks': self._analyze_technology_risks(results),
            'recommendations': self._generate_recommendations(findings),
            'learning_insights': self._extract_learning_insights(findings)
        }
        
        # Update learning data
        if self.learning_enabled:
            self._update_learning_data(findings, analysis)
            self._save_learned_data()
        
        return analysis
    
    async def _find_correlations(self, findings: List[Dict]) -> List[CorrelationResult]:
        """Find correlations between findings"""
        correlations = []
        
        # Group findings by type
        findings_by_type = defaultdict(list)
        for i, finding in enumerate(findings):
            vuln_type = finding.get('type', 'unknown')
            findings_by_type[vuln_type].append((i, finding))
        
        # Check correlation rules
        for rule in self.correlation_rules:
            required_types = rule['types']
            
            # Check if all required types are present
            if all(t in findings_by_type for t in required_types):
                finding_ids = []
                for vuln_type in required_types:
                    if findings_by_type[vuln_type]:
                        finding_ids.append(str(findings_by_type[vuln_type][0][0]))
                
                correlation = CorrelationResult(
                    finding_ids=finding_ids,
                    correlation_type=rule['name'],
                    confidence=rule['confidence'],
                    description=rule['impact'],
                    impact=rule['impact'],
                    attack_chain=rule.get('attack_chain', []),
                    remediation_priority='critical' if 'Critical' in rule['impact'] else 'high'
                )
                correlations.append(correlation)
                logger.info(f"Correlation detected: {rule['name']}")
        
        # Advanced pattern-based correlations
        pattern_correlations = self._detect_pattern_correlations(findings)
        correlations.extend(pattern_correlations)
        
        return correlations
    
    def _detect_pattern_correlations(self, findings: List[Dict]) -> List[CorrelationResult]:
        """Detect correlations based on learned patterns"""
        correlations = []
        
        # Technology concentration
        tech_findings = defaultdict(list)
        for i, finding in enumerate(findings):
            tech = finding.get('technology', 'unknown')
            if tech != 'unknown':
                tech_findings[tech].append((i, finding))
        
        for tech, tech_list in tech_findings.items():
            if len(tech_list) >= 3:
                correlation = CorrelationResult(
                    finding_ids=[str(i) for i, _ in tech_list],
                    correlation_type='Technology Concentration',
                    confidence=0.75,
                    description=f'Multiple vulnerabilities in {tech} indicate systemic issues',
                    impact=f'High - {tech} stack requires comprehensive security review',
                    remediation_priority='high'
                )
                correlations.append(correlation)
        
        # URL pattern clustering
        url_patterns = defaultdict(list)
        for i, finding in enumerate(findings):
            url = finding.get('url', '')
            # Extract path pattern
            path_pattern = re.sub(r'/\d+', '/{id}', url.split('?')[0])
            url_patterns[path_pattern].append((i, finding))
        
        for pattern, pattern_list in url_patterns.items():
            if len(pattern_list) >= 2:
                correlation = CorrelationResult(
                    finding_ids=[str(i) for i, _ in pattern_list],
                    correlation_type='Endpoint Pattern Vulnerability',
                    confidence=0.7,
                    description=f'Multiple vulnerabilities in similar endpoints: {pattern}',
                    impact='Medium - Indicates code reuse with security flaws',
                    remediation_priority='medium'
                )
                correlations.append(correlation)
        
        return correlations
    
    def _identify_attack_chains(self, findings: List[Dict]) -> List[Dict]:
        """Identify potential attack chains"""
        attack_chains = []
        
        # Pre-defined attack chain patterns
        chain_patterns = [
            {
                'name': 'Full Compromise Chain',
                'steps': ['reconnaissance', 'authentication_bypass', 'privilege_escalation', 'data_exfiltration'],
                'severity': 'critical'
            },
            {
                'name': 'Data Breach Chain',
                'steps': ['sqli', 'information_disclosure', 'sensitive_data_exposure'],
                'severity': 'critical'
            },
            {
                'name': 'Account Takeover Chain',
                'steps': ['xss', 'session_fixation', 'csrf'],
                'severity': 'high'
            },
            {
                'name': 'Infrastructure Compromise',
                'steps': ['ssrf', 'rce', 'privilege_escalation'],
                'severity': 'critical'
            }
        ]
        
        finding_types = {f.get('type', 'unknown') for f in findings}
        
        for pattern in chain_patterns:
            matched_steps = [step for step in pattern['steps'] if step in finding_types]
            if len(matched_steps) >= 2:
                attack_chains.append({
                    'name': pattern['name'],
                    'matched_steps': matched_steps,
                    'total_steps': len(pattern['steps']),
                    'completion': len(matched_steps) / len(pattern['steps']),
                    'severity': pattern['severity'],
                    'description': f"Detected {len(matched_steps)}/{len(pattern['steps'])} steps of {pattern['name']}"
                })
        
        return attack_chains
    
    def _calculate_risk_score(self, findings: List[Dict]) -> Dict[str, Any]:
        """Calculate overall risk score"""
        
        if not findings:
            return {'score': 0, 'level': 'low', 'description': 'No vulnerabilities detected'}
        
        # Severity weights
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'info': 1
        }
        
        total_score = 0
        severity_counts = defaultdict(int)
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            severity_counts[severity] += 1
            total_score += severity_weights.get(severity, 1)
        
        # Normalize score (0-100)
        max_possible = len(findings) * 10
        normalized_score = min(100, (total_score / max_possible) * 100) if max_possible > 0 else 0
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = 'critical'
        elif normalized_score >= 60:
            risk_level = 'high'
        elif normalized_score >= 40:
            risk_level = 'medium'
        elif normalized_score >= 20:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        return {
            'score': round(normalized_score, 2),
            'level': risk_level,
            'severity_breakdown': dict(severity_counts),
            'description': f'Risk score: {normalized_score:.1f}/100 ({risk_level.upper()})'
        }
    
    def _detect_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Detect potential false positives using learned patterns"""
        
        potential_fps = []
        
        for i, finding in enumerate(findings):
            fp_score = 0
            reasons = []
            
            # Check against known false positive signatures
            for fp_sig in self.false_positive_signatures:
                if self._matches_signature(finding, fp_sig):
                    fp_score += fp_sig.get('confidence', 0.5)
                    reasons.append(fp_sig.get('reason', 'Matches known FP pattern'))
            
            # Heuristic checks
            evidence = finding.get('evidence', [])
            
            # Low evidence count
            if len(evidence) < 2:
                fp_score += 0.2
                reasons.append('Insufficient evidence')
            
            # Generic error messages
            generic_errors = ['error', 'exception', 'warning', 'notice']
            if any(err in str(evidence).lower() for err in generic_errors):
                fp_score += 0.15
                reasons.append('Generic error message')
            
            # Low confidence from original detection
            if finding.get('confidence', 1.0) < 0.6:
                fp_score += 0.25
                reasons.append('Low detection confidence')
            
            if fp_score >= 0.5:
                potential_fps.append({
                    'finding_index': i,
                    'finding_title': finding.get('title', 'Unknown'),
                    'fp_probability': min(1.0, fp_score),
                    'reasons': reasons
                })
        
        return potential_fps
    
    def _matches_signature(self, finding: Dict, signature: Dict) -> bool:
        """Check if finding matches a false positive signature"""
        
        for key, pattern in signature.get('patterns', {}).items():
            finding_value = str(finding.get(key, ''))
            if not re.search(pattern, finding_value, re.IGNORECASE):
                return False
        return True
    
    def _prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize findings based on multiple factors"""
        
        prioritized = []
        
        for finding in findings:
            priority_score = 0
            
            # Severity weight
            severity_scores = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10}
            priority_score += severity_scores.get(finding.get('severity', 'info').lower(), 10)
            
            # Exploitability
            if finding.get('exploitable', False):
                priority_score += 30
            
            # Evidence strength
            evidence_count = len(finding.get('evidence', []))
            priority_score += min(20, evidence_count * 5)
            
            # Confidence
            confidence = finding.get('confidence', 0.5)
            priority_score += confidence * 20
            
            # CVSS score if available
            cvss = finding.get('cvss_score', 0)
            if isinstance(cvss, (int, float)):
                priority_score += cvss * 5
            
            prioritized.append({
                **finding,
                'priority_score': priority_score,
                'priority_rank': 0  # Will be set after sorting
            })
        
        # Sort by priority score
        prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Assign ranks
        for i, finding in enumerate(prioritized):
            finding['priority_rank'] = i + 1
        
        return prioritized
    
    def _analyze_technology_risks(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risks by technology stack"""
        
        tech_risks = defaultdict(lambda: {'count': 0, 'severities': defaultdict(int), 'findings': []})
        
        findings = results.get('vulnerabilities', [])
        for finding in findings:
            tech = finding.get('technology', 'unknown')
            severity = finding.get('severity', 'info').lower()
            
            tech_risks[tech]['count'] += 1
            tech_risks[tech]['severities'][severity] += 1
            tech_risks[tech]['findings'].append(finding.get('title', 'Unknown'))
        
        # Calculate risk score per technology
        for tech, data in tech_risks.items():
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            risk_score = sum(data['severities'][sev] * severity_weights.get(sev, 1) 
                           for sev in data['severities'])
            data['risk_score'] = risk_score
        
        return dict(tech_risks)
    
    def _generate_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation recommendations"""
        
        recommendations = []
        
        # Group by category
        by_category = defaultdict(list)
        for finding in findings:
            category = finding.get('category', 'other')
            by_category[category].append(finding)
        
        # Generate category-level recommendations
        for category, cat_findings in by_category.items():
            if not cat_findings:
                continue
            
            critical_count = sum(1 for f in cat_findings if f.get('severity') == 'critical')
            high_count = sum(1 for f in cat_findings if f.get('severity') == 'high')
            
            if critical_count > 0 or high_count > 0:
                recommendations.append({
                    'category': category,
                    'priority': 'immediate' if critical_count > 0 else 'high',
                    'finding_count': len(cat_findings),
                    'critical_count': critical_count,
                    'high_count': high_count,
                    'recommendation': self._get_category_recommendation(category),
                    'estimated_effort': self._estimate_effort(cat_findings)
                })
        
        # Sort by priority
        priority_order = {'immediate': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations
    
    def _get_category_recommendation(self, category: str) -> str:
        """Get recommendation for vulnerability category"""
        
        recommendations = {
            'injection': 'Implement input validation and parameterized queries. Use prepared statements for all database interactions.',
            'xss': 'Implement output encoding and Content Security Policy. Sanitize all user inputs before rendering.',
            'authentication': 'Implement multi-factor authentication and strong password policies. Use secure session management.',
            'authorization': 'Implement proper access controls and principle of least privilege. Validate authorization on every request.',
            'cryptography': 'Use strong encryption algorithms and proper key management. Implement TLS 1.3 for all communications.',
            'configuration': 'Follow security hardening guidelines. Remove default credentials and unnecessary services.',
            'sensitive_data': 'Implement data classification and encryption at rest. Use secure data transmission protocols.'
        }
        
        return recommendations.get(category, 'Review and remediate identified vulnerabilities following security best practices.')
    
    def _estimate_effort(self, findings: List[Dict]) -> str:
        """Estimate remediation effort"""
        
        total_findings = len(findings)
        
        if total_findings >= 10:
            return 'High (2-4 weeks)'
        elif total_findings >= 5:
            return 'Medium (1-2 weeks)'
        else:
            return 'Low (2-5 days)'
    
    def _extract_learning_insights(self, findings: List[Dict]) -> Dict[str, Any]:
        """Extract insights for learning system"""
        
        insights = {
            'new_patterns': [],
            'pattern_updates': [],
            'accuracy_feedback': {}
        }
        
        # Identify new vulnerability patterns
        for finding in findings:
            pattern_key = f"{finding.get('type', 'unknown')}_{finding.get('technology', 'unknown')}"
            
            # Check if this is a new pattern
            existing_pattern = next(
                (p for p in self.learned_patterns if p.pattern_type == pattern_key),
                None
            )
            
            if not existing_pattern:
                insights['new_patterns'].append({
                    'pattern_type': pattern_key,
                    'indicators': finding.get('evidence', [])[:3],
                    'confidence': finding.get('confidence', 0.7)
                })
        
        return insights
    
    def _update_learning_data(self, findings: List[Dict], analysis: Dict[str, Any]):
        """Update learning data based on scan results"""
        
        if not self.learning_enabled:
            return
        
        # Update pattern occurrences
        for finding in findings:
            pattern_key = f"{finding.get('type', 'unknown')}_{finding.get('technology', 'unknown')}"
            
            existing = next(
                (p for p in self.learned_patterns if p.pattern_type == pattern_key),
                None
            )
            
            if existing:
                existing.occurrences += 1
                existing.last_seen = datetime.now().isoformat()
            else:
                new_pattern = LearnedPattern(
                    pattern_type=pattern_key,
                    indicators=finding.get('evidence', [])[:3],
                    confidence=finding.get('confidence', 0.7),
                    false_positive_rate=0.0,
                    occurrences=1,
                    last_seen=datetime.now().isoformat()
                )
                self.learned_patterns.append(new_pattern)
        
        # Update false positive data
        for fp in analysis.get('false_positives', []):
            if fp['fp_probability'] >= 0.7:
                finding_idx = fp['finding_index']
                if finding_idx < len(findings):
                    finding = findings[finding_idx]
                    fp_signature = {
                        'patterns': {
                            'title': finding.get('title', ''),
                            'type': finding.get('type', '')
                        },
                        'confidence': fp['fp_probability'],
                        'reason': ', '.join(fp['reasons'])
                    }
                    self.false_positive_signatures.append(fp_signature)
        
        logger.info(f"Updated learning data: {len(self.learned_patterns)} patterns")
    
    async def cleanup(self):
        """Cleanup and save final state"""
        if self.learning_enabled:
            self._save_learned_data()
        logger.info("AI analyzer cleanup complete")


# Import for datetime
from datetime import datetime
