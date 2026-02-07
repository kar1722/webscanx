# ai/injection_engine.py
import asyncio
import time
import re
from typing import Dict, List, Any, Optional, Tuple
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging

from payload_generator import AIPayloadGenerator, PayloadContext

logger = logging.getLogger(__name__)

class AdaptiveInjectionEngine:
    
    def __init__(self, http_client, config):
        self.http_client = http_client
        self.config = config
        self.payload_generator = AIPayloadGenerator()
        self.learning_data = {}
        self.injection_history = {}
        
    async def test_injection(self, url: str, param: str, param_value: str, vulnerability_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        
        payload_context = PayloadContext(
            technology=context.get('technology', 'unknown'),
            waf_detected=context.get('waf_detected', False),
            waf_type=context.get('waf_type'),
            previous_payloads=self.injection_history.get(url, {}).get(param, [])
        )
        

        payloads = self.payload_generator.generate_contextual_payloads(
            vulnerability_type, payload_context
        )
        
        results = {
            'url': url,
            'parameter': param,
            'vulnerability_type': vulnerability_type,
            'tested_payloads': [],
            'vulnerable': False,
            'confidence': 0.0,
            'evidence': []
        }
        
        # Round 1: اختبار بايلودات خفيفة وسريعة
        logger.info(f"Round 1: Testing lightweight payloads for {param}")
        round1_results = await self._test_payloads_round1(url, param, param_value, payloads[:5])
        results['tested_payloads'].extend(round1_results['tested_payloads'])
        
        if round1_results['vulnerable']:
            results['vulnerable'] = True
            results['confidence'] = max(results['confidence'], 0.7)
            results['evidence'].extend(round1_results['evidence'])
            self._update_learning_data(url, param, round1_results, success=True)
            return results
        
        # Round 2: إذا فشل Round 1، نغير الأسلوب
        logger.info(f"Round 2: Changing approach for {param}")
        round2_results = await self._test_payloads_round2(url, param, param_value, payloads[5:10])
        results['tested_payloads'].extend(round2_results['tested_payloads'])
        
        if round2_results['vulnerable']:
            results['vulnerable'] = True
            results['confidence'] = max(results['confidence'], 0.8)
            results['evidence'].extend(round2_results['evidence'])
            self._update_learning_data(url, param, round2_results, success=True)
            return results
        
        # Round 3: Time-based detection (فقط في الوضع العميق)
        if self.config.get('scan.mode') in ['deep', 'ai']:
            logger.info(f"Round 3: Time-based detection for {param}")
            round3_results = await self._test_time_based(url, param, param_value, payloads[10:15])
            results['tested_payloads'].extend(round3_results['tested_payloads'])
            
            if round3_results['vulnerable']:
                results['vulnerable'] = True
                results['confidence'] = max(results['confidence'], 0.9)
                results['evidence'].extend(round3_results['evidence'])
                self._update_learning_data(url, param, round3_results, success=True)
                return results
        

        self._update_learning_data(url, param, results, success=False)
        return results
    
    async def _test_payloads_round1(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:
        
        results = {
            'vulnerable': False,
            'tested_payloads': [],
            'evidence': []
        }
        
        for payload_info in payloads:
            payload = payload_info['obfuscated']
            

            test_url = self._build_test_url(url, param, payload)
            
            try:

                start_time = time.time()
                response = await self.http_client.get(test_url)
                end_time = time.time()
                
                response_time = end_time - start_time
                response_text = await response.text()
                

                analysis = self._analyze_response(
                    response, response_text, response_time, payload
                )
                

                test_result = {
                    'payload': payload,
                    'technique': payload_info['technique_used'],
                    'response_time': response_time,
                    'status_code': response.status,
                    'analysis': analysis
                }
                
                results['tested_payloads'].append(test_result)
                

                if analysis['indicators_found']:
                    results['vulnerable'] = True
                    results['evidence'].append({
                        'payload': payload,
                        'indicators': analysis['indicators'],
                        'response_time': response_time,
                        'status_code': response.status
                    })
                    break
                    
            except Exception as e:
                logger.debug(f"Payload test failed: {e}")
                continue
        
        return results
    
    async def _test_payloads_round2(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:
        
        results = {
            'vulnerable': False,
            'tested_payloads': [],
            'evidence': []
        }
        

        test_methods = [
            self._test_with_different_param_location,
            self._test_with_parameter_pollution,
            self._test_with_header_injection
        ]
        
        for method in test_methods:
            if results['vulnerable']:
                break
                
            method_results = await method(url, param, param_value, payloads)
            results['tested_payloads'].extend(method_results['tested_payloads'])
            
            if method_results['vulnerable']:
                results['vulnerable'] = True
                results['evidence'].extend(method_results['evidence'])
                break
        
        return results
    
    async def _test_time_based(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:
        
        results = {
            'vulnerable': False,
            'tested_payloads': [],
            'evidence': []
        }
        

        baseline_time = await self._get_baseline_response_time(url, param, param_value)
        
        for payload_info in payloads:
            payload = payload_info['obfuscated']
            

            time_payloads = self._generate_time_based_payloads(payload)
            
            for time_payload in time_payloads:
                test_url = self._build_test_url(url, param, time_payload)
                
                try:
                    start_time = time.time()
                    response = await self.http_client.get(test_url)
                    end_time = time.time()
                    
                    response_time = end_time - start_time
                    

                    if response_time > baseline_time * 2:  
                        results['vulnerable'] = True
                        results['evidence'].append({
                            'payload': time_payload,
                            'baseline_time': baseline_time,
                            'response_time': response_time,
                            'delay_multiplier': response_time / baseline_time
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"Time-based test failed: {e}")
                    continue
            
            if results['vulnerable']:
                break
        
        return results
    
    async def _get_baseline_response_time(self, url: str, param: str, param_value: str) -> float:

        try:
            baseline_url = self._build_test_url(url, param, param_value)
            
            times = []
            for _ in range(3):  
                start_time = time.time()
                response = await self.http_client.get(baseline_url)
                await response.text()  # قراءة الرد بالكامل
                end_time = time.time()
                times.append(end_time - start_time)
            
            return sum(times) / len(times)
        except Exception as e:
            logger.debug(f"Baseline time failed: {e}")
            return 0.5  # وقت افتراضي
    
    def _generate_time_based_payloads(self, base_payload: str) -> List[str]:

        time_payloads = []
        

        delay_commands = [
            ('mysql', " AND SLEEP(5)--"),
            ('mysql', "' AND SLEEP(5)--"),
            ('mssql', ";WAITFOR DELAY '0:0:5'--"),
            ('postgresql', "; SELECT pg_sleep(5)--"),
            ('oracle', "; DBMS_LOCK.SLEEP(5)--"),
        ]
        
        for db, delay in delay_commands:
            if db in ['mysql', 'postgresql']:
                time_payloads.append(base_payload + delay)
        
        return time_payloads
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:

        from urllib.parse import urlparse, parse_qs, urlencode
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        params[param] = payload

        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _analyze_response(self, response, response_text: str, response_time: float, payload: str) -> Dict[str, Any]:

        indicators = []
        
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]+",
            r"Microsoft.*OLE DB",
            r"unclosed quotation mark",
            r"syntax error"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(f"error_pattern: {pattern}")
        
        if response_time > 5:  # إذا كان وقت الاستجابة كبير
            indicators.append(f"high_response_time: {response_time}")
        
        if response.status in [500, 501, 502]:
            indicators.append(f"suspicious_status: {response.status}")
        
        return {
            'indicators': indicators,
            'indicators_found': len(indicators) > 0,
            'response_length': len(response_text),
            'response_time': response_time
        }
    
    async def _test_with_different_param_location(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:
       
        return {'vulnerable': False, 'tested_payloads': [], 'evidence': []}
    
    async def _test_with_parameter_pollution(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:

        # HTTP Parameter Pollution testing
        return {'vulnerable': False, 'tested_payloads': [], 'evidence': []}
    
    async def _test_with_header_injection(self, url: str, param: str, param_value: str, payloads: List[Dict]) -> Dict[str, Any]:
    
        # Header injection testing
        return {'vulnerable': False, 'tested_payloads': [], 'evidence': []}
    
    def _update_learning_data(self, url: str, param: str, results: Dict[str, Any], success: bool):

        if url not in self.learning_data:
            self.learning_data[url] = {}
        
        if param not in self.learning_data[url]:
            self.learning_data[url][param] = []
        
        self.learning_data[url][param].append({
            'timestamp': time.time(),
            'success': success,
            'payloads_tested': len(results.get('tested_payloads', [])),
            'evidence': results.get('evidence', [])
        })
        
        if len(self.learning_data[url][param]) > 10:
            self.learning_data[url][param] = self.learning_data[url][param][-10:]
