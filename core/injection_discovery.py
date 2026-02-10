#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
نظام اكتشاف نقاط الحقن المتقدم
Advanced Injection Point Discovery System
"""

import re
import json
import logging
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ParamType(Enum):
    """أنواع الباراميترات"""
    QUERY = "query"           # URL query parameter
    FORM = "form"             # Form field
    JSON = "json"             # JSON body parameter
    HEADER = "header"         # HTTP Header
    PATH = "path"             # Path variable (RESTful)
    COOKIE = "cookie"         # Cookie value
    XML = "xml"               # XML body parameter
    MULTIPART = "multipart"   # Multipart form data


@dataclass
class InjectionPoint:
    """نقطة حقن محتملة"""
    url: str
    method: str
    param_name: str
    param_type: ParamType
    source: str               # مصدر الاكتشاف
    confidence: float = 1.0   # مستوى الثقة (0.0 - 1.0)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل لقاموس"""
        return {
            'url': self.url,
            'method': self.method,
            'param_name': self.param_name,
            'param_type': self.param_type.value,
            'source': self.source,
            'confidence': self.confidence,
            'context': self.context
        }
    
    def get_test_url(self, payload: str) -> str:
        """بناء URL للاختبار مع الحمولة"""
        parsed = urlparse(self.url)
        
        if self.param_type == ParamType.QUERY:
            params = parse_qs(parsed.query)
            params[self.param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        return self.url
    
    def get_fingerprint(self) -> str:
        """بصمة فريدة لنقطة الحقن"""
        return f"{self.method}:{self.url}:{self.param_name}:{self.param_type.value}"


class InjectionPointDiscovery:
    """محرك اكتشاف نقاط الحقن المتقدم"""
    
    # أنماط اكتشاف API endpoints
    API_PATTERNS = [
        (r'/api/[v\d]*/\w+', 'rest_api'),
        (r'/rest/\w+', 'rest_endpoint'),
        (r'/graphql[/?]?', 'graphql'),
        (r'/swagger\.json', 'swagger'),
        (r'/api-docs', 'api_docs'),
        (r'/_next/data/[\w/]+', 'nextjs_data'),
        (r'/__data\.json', 'svelte_data'),
        (r'/wp-json/wp/v\d/\w+', 'wordpress_api'),
        (r'/index\.php\?rest_route=/', 'wordpress_rest'),
    ]
    
    # أنماط اكتشاف parameters في JavaScript
    JS_PARAM_PATTERNS = [
        # React/Vue/Angular patterns
        (r'["\'](\w+)["\']\s*:\s*["\'][^"\']*["\']', 'json_like'),
        (r'params\.(\w+)', 'params_object'),
        (r'query\.(\w+)', 'query_object'),
        (r'searchParams\.get\(["\'](\w+)["\']', 'url_search_params'),
        (r'useSearchParams\(\)\.get\(["\'](\w+)["\']', 'react_search_params'),
        
        # Express.js patterns
        (r'req\.query\.(\w+)', 'express_query'),
        (r'req\.body\.(\w+)', 'express_body'),
        (r'req\.params\.(\w+)', 'express_params'),
        
        # Fetch/Axios patterns
        (r'\.get\(["\']([^"\']+)["\']', 'http_get'),
        (r'\.post\(["\']([^"\']+)["\']', 'http_post'),
        (r'\.put\(["\']([^"\']+)["\']', 'http_put'),
        (r'\.delete\(["\']([^"\']+)["\']', 'http_delete'),
        
        # jQuery patterns
        (r'\$\.get\(["\']([^"\']+)["\']', 'jquery_get'),
        (r'\$\.post\(["\']([^"\']+)["\']', 'jquery_post'),
        (r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jquery_ajax'),
        
        # Generic API calls
        (r'fetch\(["\']([^"\']+)["\']', 'fetch_api'),
        (r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']', 'axios_call'),
        
        # GraphQL
        (r'query\s+\w+\s*\([^)]*(\$\w+)', 'graphql_var'),
        (r'mutation\s+\w+\s*\([^)]*(\$\w+)', 'graphql_mutation_var'),
    ]
    
    # أنماط اكتشاف RESTful parameters في الـ path
    REST_PATTERNS = [
        (r'/(\d+)', 'numeric_id'),           # /123
        (r'/([0-9a-f]{8,})', 'uuid'),        # /550e8400-e29b-41d4-a716-446655440000
        (r'/(\w+-\w+)', 'slug'),             # /my-post-title
        (r'/([a-z]+_\d+)', 'named_id'),      # /user_123
    ]
    
    # أنماط اكتشاف parameters في الـ HTML
    HTML_INPUT_PATTERNS = [
        (r'<input[^>]*name=["\']([^"\']+)["\']', 'input'),
        (r'<select[^>]*name=["\']([^"\']+)["\']', 'select'),
        (r'<textarea[^>]*name=["\']([^"\']+)["\']', 'textarea'),
        (r'<button[^>]*name=["\']([^"\']+)["\']', 'button'),
    ]
    
    # أنماط اكتشاف parameters في JSON responses
    JSON_PARAM_PATTERNS = [
        (r'"(\w+)"\s*:\s*"[^"]*"', 'string_field'),
        (r'"(\w+)"\s*:\s*\d+', 'number_field'),
        (r'"(\w+)"\s*:\s*\[', 'array_field'),
        (r'"(\w+)"\s*:\s*\{', 'object_field'),
        (r'"(\w+)"\s*:\s*(?:true|false|null)', 'boolean_field'),
    ]
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.base_domain = self.parsed_base.netloc
        
        # تخزين النتائج
        self.injection_points: List[InjectionPoint] = []
        self.discovered_urls: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        
        # تتبع المصادر
        self.source_stats: Dict[str, int] = {}
        
        logger.debug(f"InjectionPointDiscovery initialized for {base_url}")
    
    # ==================== اكتشاف من URL ====================
    
    def discover_from_url(self, url: str, source: str = "url_analysis") -> List[InjectionPoint]:
        """اكتشاف نقاط حقن من URL"""
        points = []
        parsed = urlparse(url)
        
        logger.debug(f"Analyzing URL: {url}")
        
        # 1. اكتشاف parameters من query string
        if parsed.query:
            query_points = self._extract_query_params(url, parsed.query, source)
            points.extend(query_points)
        
        # 2. اكتشاف RESTful parameters من الـ path
        path_points = self._extract_path_params(url, parsed.path, source)
        points.extend(path_points)
        
        # 3. اكتشاف API endpoints
        api_points = self._detect_api_endpoint(url, parsed.path, source)
        points.extend(api_points)
        
        # 4. اكتشاف hash-based routing (React Router, etc.)
        if parsed.fragment:
            hash_points = self._extract_hash_params(url, parsed.fragment, source)
            points.extend(hash_points)
        
        # تسجيل URL كمكتشف
        self.discovered_urls.add(url)
        self._update_stats(source, len(points))
        
        return points
    
    def _extract_query_params(self, url: str, query: str, source: str) -> List[InjectionPoint]:
        """استخراج باراميترات الـ query string"""
        points = []
        
        try:
            params = parse_qs(query, keep_blank_values=True)
            
            for param_name, values in params.items():
                # تجاهل باراميترات التتبع الشائعة
                if self._is_tracking_param(param_name):
                    continue
                
                for value in values:
                    point = InjectionPoint(
                        url=url.split('?')[0],
                        method='GET',
                        param_name=param_name,
                        param_type=ParamType.QUERY,
                        source=f"{source}:query",
                        confidence=0.95,
                        context={
                            'original_value': value,
                            'value_type': self._detect_value_type(value),
                            'multiple_values': len(values) > 1
                        }
                    )
                    points.append(point)
                    self.discovered_params.add(param_name)
                    logger.debug(f"Found query param: {param_name}")
        
        except Exception as e:
            logger.warning(f"Failed to parse query string: {e}")
        
        return points
    
    def _extract_path_params(self, url: str, path: str, source: str) -> List[InjectionPoint]:
        """استخراج باراميترات الـ path (RESTful)"""
        points = []
        
        path_parts = path.strip('/').split('/')
        
        for i, part in enumerate(path_parts):
            if not part:
                continue
            
            confidence = 0.5
            param_type = 'unknown'
            param_name = f"path_{i}"
            
            # التحقق من أنماط RESTful
            for pattern, ptype in self.REST_PATTERNS:
                if re.match(pattern, f'/{part}'):
                    confidence = 0.85
                    param_type = ptype
                    
                    # تسمية ذكية حسب السياق
                    if i > 0:
                        prev_part = path_parts[i-1].lower()
                        if ptype == 'numeric_id':
                            param_name = f"{prev_part}_id"
                        elif ptype == 'uuid':
                            param_name = f"{prev_part}_uuid"
                        elif ptype == 'slug':
                            param_name = f"{prev_part}_slug"
                    break
            
            # إذا كان الجزء يبدو كـ ID
            if part.isdigit() or re.match(r'^[0-9a-f]{8,}$', part, re.I):
                point = InjectionPoint(
                    url=url,
                    method='GET',
                    param_name=param_name,
                    param_type=ParamType.PATH,
                    source=f"{source}:path",
                    confidence=confidence,
                    context={
                        'path_position': i,
                        'value': part,
                        'detected_type': param_type,
                        'full_path': path
                    }
                )
                points.append(point)
                logger.debug(f"Found path param: {param_name} = {part}")
        
        return points
    
    def _detect_api_endpoint(self, url: str, path: str, source: str) -> List[InjectionPoint]:
        """اكتشاف API endpoints"""
        points = []
        
        for pattern, api_type in self.API_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                self.api_endpoints.add(url)
                logger.info(f"Detected API endpoint ({api_type}): {url}")
                
                # إضافة نقطة حقن خاصة للـ API
                point = InjectionPoint(
                    url=url,
                    method='GET',
                    param_name='api_endpoint',
                    param_type=ParamType.PATH,
                    source=f"{source}:api_detection",
                    confidence=0.9,
                    context={
                        'api_type': api_type,
                        'path_pattern': pattern
                    }
                )
                points.append(point)
                break
        
        return points
    
    def _extract_hash_params(self, url: str, fragment: str, source: str) -> List[InjectionPoint]:
        """استخراج باراميترات من hash fragment"""
        points = []
        
        # بعض التطبيقات تستخدم hash routing مع parameters
        # مثال: #/page?id=123&view=detail
        
        if '?' in fragment:
            hash_query = fragment.split('?')[1]
            hash_points = self._extract_query_params(url, hash_query, f"{source}:hash")
            points.extend(hash_points)
        
        return points
    
    # ==================== اكتشاف من HTML ====================
    
    def discover_from_html(self, url: str, html: str, source: str = "html_analysis") -> List[InjectionPoint]:
        """اكتشاف نقاط حقن من HTML"""
        points = []
        
        logger.debug(f"Analyzing HTML from {url} ({len(html)} chars)")
        
        # 1. استخراج Forms
        form_points = self._extract_forms(url, html, source)
        points.extend(form_points)
        
        # 2. استخراج روابط بـ parameters
        link_points = self._extract_links_with_params(url, html, source)
        points.extend(link_points)
        
        # 3. استخراج JavaScript inline
        js_points = self._extract_inline_javascript(url, html, source)
        points.extend(js_points)
        
        # 4. استخراج meta tags
        meta_points = self._extract_meta_params(url, html, source)
        points.extend(meta_points)
        
        # 5. استخراج data attributes
        data_points = self._extract_data_attributes(url, html, source)
        points.extend(data_points)
        
        self._update_stats(source, len(points))
        
        return points
    
    def _extract_forms(self, url: str, html: str, source: str) -> List[InjectionPoint]:
        """استخراج نماذج HTML"""
        points = []
        
        # Regex لاستخراج Forms كاملة
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            form_content = form_match.group(1)
            
            # استخراج خصائص الـ form
            form_attrs = self._parse_html_attrs(form_html)
            
            action = form_attrs.get('action', '')
            method = form_attrs.get('method', 'GET').upper()
            form_id = form_attrs.get('id', '')
            form_name = form_attrs.get('name', '')
            
            # تنظيف الـ action
            if not action or action == '#' or action.startswith('javascript:'):
                action = url
            else:
                action = urljoin(url, action)
            
            # استخراج inputs
            input_points = self._extract_form_inputs(action, method, form_content, 
                                                      form_id, form_name, source)
            points.extend(input_points)
        
        return points
    
    def _extract_form_inputs(self, action: str, method: str, form_content: str,
                            form_id: str, form_name: str, source: str) -> List[InjectionPoint]:
        """استخراج حقول النموذج"""
        points = []
        
        for pattern, input_type in self.HTML_INPUT_PATTERNS:
            for match in re.finditer(pattern, form_content, re.IGNORECASE):
                input_html = match.group(0)
                param_name = match.group(1)
                
                attrs = self._parse_html_attrs(input_html)
                
                # تجاهل الأزرار والحقول المخفية الروتينية
                input_type_attr = attrs.get('type', 'text').lower()
                if input_type_attr in ['submit', 'button', 'image', 'reset']:
                    continue
                
                # تجاهل CSRF tokens (للاختبار فقط، لا للحقن)
                if self._is_csrf_token(param_name):
                    continue
                
                point = InjectionPoint(
                    url=action,
                    method=method,
                    param_name=param_name,
                    param_type=ParamType.FORM,
                    source=f"{source}:form_{input_type}",
                    confidence=1.0,
                    context={
                        'form_id': form_id,
                        'form_name': form_name,
                        'input_type': input_type_attr,
                        'required': 'required' in input_html.lower() or attrs.get('required'),
                        'placeholder': attrs.get('placeholder', ''),
                        'pattern': attrs.get('pattern', '')
                    }
                )
                points.append(point)
                self.discovered_params.add(param_name)
                logger.debug(f"Found form input: {param_name} ({input_type})")
        
        return points
    
    def _extract_links_with_params(self, base_url: str, html: str, source: str) -> List[InjectionPoint]:
        """استخراج روابط تحتوي على parameters"""
        points = []
        
        # البحث عن روابط href
        href_pattern = r'href=["\']([^"\']+)["\']'
        
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            link = match.group(1)
            
            # تجاهل الروابط الخارجية والـ javascript
            if link.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
                continue
            
            absolute = urljoin(base_url, link)
            
            # التحقق من نفس الدومين
            if urlparse(absolute).netloc != self.base_domain:
                continue
            
            # اكتشاف parameters من الرابط
            link_points = self.discover_from_url(absolute, f"{source}:link")
            points.extend(link_points)
        
        return points
    
    def _extract_inline_javascript(self, url: str, html: str, source: str) -> List[InjectionPoint]:
        """استخراج JavaScript inline"""
        points = []
        
        # استخراج محتوى الـ script tags
        script_pattern = r'<script[^>]*>(.*?)</script>'
        
        for match in re.finditer(script_pattern, html, re.DOTALL | re.IGNORECASE):
            script_content = match.group(1)
            if script_content.strip():
                js_points = self.discover_from_javascript(url, script_content, 
                                                          f"{source}:inline")
                points.extend(js_points)
        
        return points
    
    def _extract_meta_params(self, url: str, html: str, source: str) -> List[InjectionPoint]:
        """استخراج parameters من meta tags"""
        points = []
        
        # meta refresh مع URL
        meta_refresh_pattern = r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']+)["\']'
        
        for match in re.finditer(meta_refresh_pattern, html, re.IGNORECASE):
            content = match.group(1)
            if 'url=' in content.lower():
                redirect_url = content.split('url=')[-1].strip()
                absolute = urljoin(url, redirect_url)
                points.extend(self.discover_from_url(absolute, f"{source}:meta_refresh"))
        
        return points
    
    def _extract_data_attributes(self, url: str, html: str, source: str) -> List[InjectionPoint]:
        """استخراج data attributes التي قد تحتوي على parameters"""
        points = []
        
        # البحث عن data-* attributes
        data_pattern = r'data-(\w+)=["\']([^"\']+)["\']'
        
        for match in re.finditer(data_pattern, html, re.IGNORECASE):
            attr_name = match.group(1)
            attr_value = match.group(2)
            
            # إذا كانت القيمة تبدو كـ URL مع parameters
            if '?' in attr_value or attr_value.startswith('/'):
                absolute = urljoin(url, attr_value)
                points.extend(self.discover_from_url(absolute, f"{source}:data_attr"))
        
        return points
    
    # ==================== اكتشاف من JavaScript ====================
    
    def discover_from_javascript(self, url: str, js_code: str, 
                                  source: str = "js_analysis") -> List[InjectionPoint]:
        """اكتشاف نقاط حقن من كود JavaScript"""
        points = []
        
        logger.debug(f"Analyzing JavaScript ({len(js_code)} chars)")
        
        # 1. اكتشاف API calls
        api_points = self._extract_api_calls(url, js_code, source)
        points.extend(api_points)
        
        # 2. اكتشاف parameters من المتغيرات
        var_points = self._extract_js_variables(url, js_code, source)
        points.extend(var_points)
        
        # 3. اكتشاف GraphQL
        graphql_points = self._extract_graphql_params(url, js_code, source)
        points.extend(graphql_points)
        
        # 4. اكتشاف template strings
        template_points = self._extract_template_literals(url, js_code, source)
        points.extend(template_points)
        
        self._update_stats(source, len(points))
        
        return points
    
    def _extract_api_calls(self, url: str, js_code: str, source: str) -> List[InjectionPoint]:
        """استخراج API calls من JavaScript"""
        points = []
        
        for pattern, call_type in self.JS_PARAM_PATTERNS:
            for match in re.finditer(pattern, js_code, re.IGNORECASE):
                if call_type.startswith('http_') or call_type in ['fetch_api', 'axios_call']:
                    # هذا API URL
                    api_url = match.group(1)
                    full_url = urljoin(url, api_url)
                    
                    # اكتشاف parameters من الـ URL
                    url_points = self.discover_from_url(full_url, f"{source}:{call_type}")
                    points.extend(url_points)
                    
                    # إضافة كـ API endpoint
                    if full_url not in self.api_endpoints:
                        self.api_endpoints.add(full_url)
                        logger.info(f"Found API call ({call_type}): {full_url}")
                else:
                    # هذا اسم parameter
                    param_name = match.group(1)
                    if param_name not in self.discovered_params:
                        point = InjectionPoint(
                            url=url,
                            method='POST',  # افتراضي
                            param_name=param_name,
                            param_type=ParamType.JSON,
                            source=f"{source}:{call_type}",
                            confidence=0.7,
                            context={'js_pattern': pattern}
                        )
                        points.append(point)
                        self.discovered_params.add(param_name)
        
        return points
    
    def _extract_js_variables(self, url: str, js_code: str, source: str) -> List[InjectionPoint]:
        """استخراج parameters من متغيرات JavaScript"""
        points = []
        
        # البحث عن كائنات الإعدادات الشائعة
        config_patterns = [
            (r'const\s+config\s*=\s*\{([^}]+)\}', 'const_config'),
            (r'var\s+config\s*=\s*\{([^}]+)\}', 'var_config'),
            (r'let\s+config\s*=\s*\{([^}]+)\}', 'let_config'),
            (r'window\.__CONFIG__\s*=\s*(\{[^}]+\})', 'window_config'),
            (r'window\.__INITIAL_STATE__\s*=\s*(\{[^}]+\})', 'redux_state'),
        ]
        
        for pattern, config_type in config_patterns:
            for match in re.finditer(pattern, js_code, re.DOTALL):
                config_content = match.group(1)
                # استخراج المفاتيح
                key_pattern = r'(\w+)\s*:'
                for key_match in re.finditer(key_pattern, config_content):
                    key = key_match.group(1)
                    if key not in self.discovered_params and not key.startswith('_'):
                        point = InjectionPoint(
                            url=url,
                            method='POST',
                            param_name=key,
                            param_type=ParamType.JSON,
                            source=f"{source}:{config_type}",
                            confidence=0.6,
                            context={'found_in': config_type}
                        )
                        points.append(point)
                        self.discovered_params.add(key)
        
        return points
    
    def _extract_graphql_params(self, url: str, js_code: str, source: str) -> List[InjectionPoint]:
        """استخراج parameters من GraphQL queries"""
        points = []
        
        # البحث عن GraphQL queries
        graphql_pattern = r'(query|mutation)\s+(\w+)\s*\(([^)]*)\)'
        
        for match in re.finditer(graphql_pattern, js_code, re.IGNORECASE):
            operation_type = match.group(1)
            operation_name = match.group(2)
            args = match.group(3)
            
            # استخراج الـ variables من الـ arguments
            var_pattern = r'(\$\w+)'
            for var_match in re.finditer(var_pattern, args):
                var_name = var_match.group(1).lstrip('$')
                
                point = InjectionPoint(
                    url=url,
                    method='POST',
                    param_name=var_name,
                    param_type=ParamType.JSON,
                    source=f"{source}:graphql_{operation_type}",
                    confidence=0.8,
                    context={
                        'graphql_operation': operation_name,
                        'operation_type': operation_type
                    }
                )
                points.append(point)
                self.discovered_params.add(var_name)
                logger.debug(f"Found GraphQL variable: {var_name}")
        
        return points
    
    def _extract_template_literals(self, url: str, js_code: str, source: str) -> List[InjectionPoint]:
        """استخراج parameters من template literals"""
        points = []
        
        # البحث عن template literals مع variables
        template_pattern = r'`([^`]*\$\{[^}]+\}[^`]*)`'
        
        for match in re.finditer(template_pattern, js_code):
            template = match.group(1)
            
            # استخراج الـ variables
            var_pattern = r'\$\{(\w+)\}'
            for var_match in re.finditer(var_pattern, template):
                var_name = var_match.group(1)
                
                # إذا كان الـ template يحتوي على URL
                if '/' in template or 'http' in template:
                    point = InjectionPoint(
                        url=url,
                        method='GET',
                        param_name=var_name,
                        param_type=ParamType.PATH,
                        source=f"{source}:template_literal",
                        confidence=0.65,
                        context={'template': template[:100]}
                    )
                    points.append(point)
        
        return points
    
    # ==================== اكتشاف من API Response ====================
    
    def discover_from_api_response(self, url: str, response_data: Any, 
                                    source: str = "api_response") -> List[InjectionPoint]:
        """اكتشاف parameters من API response"""
        points = []
        
        logger.debug(f"Analyzing API response from {url}")
        
        if isinstance(response_data, dict):
            dict_points = self._extract_from_dict(url, response_data, source)
            points.extend(dict_points)
        elif isinstance(response_data, list) and response_data:
            # إذا كانت قائمة، نحلل العنصر الأول
            if isinstance(response_data[0], dict):
                dict_points = self._extract_from_dict(url, response_data[0], source)
                points.extend(dict_points)
        
        self._update_stats(source, len(points))
        
        return points
    
    def _extract_from_dict(self, url: str, data: dict, source: str, 
                          prefix: str = '') -> List[InjectionPoint]:
        """استخراج parameters من قاموس متداخل"""
        points = []
        
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                # متابعة التعمق
                nested_points = self._extract_from_dict(url, value, source, full_key)
                points.extend(nested_points)
            elif isinstance(value, list) and value and isinstance(value[0], dict):
                # قائمة من الكائنات
                nested_points = self._extract_from_dict(url, value[0], source, full_key)
                points.extend(nested_points)
            else:
                # هذا الـ key قد يكون parameter للـ POST/PUT
                point = InjectionPoint(
                    url=url,
                    method='POST',
                    param_name=full_key,
                    param_type=ParamType.JSON,
                    source=source,
                    confidence=0.75,
                    context={
                        'sample_value': str(value)[:100],
                        'value_type': type(value).__name__
                    }
                )
                points.append(point)
                self.discovered_params.add(full_key)
        
        return points
    
    # ==================== اكتشاف من Headers ====================
    
    def discover_from_headers(self, url: str, headers: dict, 
                               source: str = "header_analysis") -> List[InjectionPoint]:
        """اكتشاف parameters محتملة من HTTP headers"""
        points = []
        
        # Headers قد تحتوي على tokens أو IDs يمكن استغلالها
        interesting_headers = [
            'X-User-ID', 'X-User-Id', 'X-UserId',
            'X-Account-ID', 'X-Account-Id',
            'X-Session-ID', 'X-Session-Id',
            'X-Request-ID', 'X-Request-Id',
            'X-Correlation-ID', 'X-Correlation-Id',
            'X-CSRF-Token', 'X-XSRF-Token',
            'Authorization', 'X-API-Key', 'X-Api-Key',
        ]
        
        for header_name in interesting_headers:
            if header_name in headers:
                point = InjectionPoint(
                    url=url,
                    method='GET',
                    param_name=header_name,
                    param_type=ParamType.HEADER,
                    source=source,
                    confidence=0.6,
                    context={
                        'header_value_preview': str(headers[header_name])[:20]
                    }
                )
                points.append(point)
        
        return points
    
    # ==================== دوال مساعدة ====================
    
    def _parse_html_attrs(self, html_tag: str) -> Dict[str, str]:
        """تحليل خصائص HTML tag"""
        attrs = {}
        
        # Regex لاستخراج الخصائص
        attr_pattern = r'(\w+)=["\']([^"\']*)["\']'
        
        for match in re.finditer(attr_pattern, html_tag):
            attr_name = match.group(1).lower()
            attr_value = match.group(2)
            attrs[attr_name] = attr_value
        
        return attrs
    
    def _is_tracking_param(self, param_name: str) -> bool:
        """التحقق إذا كان الباراميتر للتتبع فقط"""
        tracking_params = {
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'ttclid', 'msclkid',
            'ref', 'referrer', 'source', 'medium',
            'cid', 'sid', 'sessionid', 'visitorid',
            '_ga', '_gid', '_gat', '__utma', '__utmb', '__utmc', '__utmz',
        }
        return param_name.lower() in tracking_params
    
    def _is_csrf_token(self, param_name: str) -> bool:
        """التحقق إذا كان الباراميتر CSRF token"""
        csrf_names = {
            'csrf_token', 'csrfmiddlewaretoken', '_token', 'authenticity_token',
            '__requestverificationtoken', '_csrf', 'csrf', 'xsrf_token',
        }
        return param_name.lower() in csrf_names
    
    def _detect_value_type(self, value: str) -> str:
        """تحديد نوع القيمة"""
        if value.isdigit():
            return 'integer'
        if re.match(r'^\d+\.\d+$', value):
            return 'float'
        if re.match(r'^(true|false)$', value, re.I):
            return 'boolean'
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return 'date'
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return 'uuid'
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email'
        if len(value) > 100:
            return 'long_text'
        return 'string'
    
    def _update_stats(self, source: str, count: int):
        """تحديث إحصائيات المصادر"""
        self.source_stats[source] = self.source_stats.get(source, 0) + count
    
    # ==================== الحصول على النتائج ====================
    
    def get_all_points(self) -> List[InjectionPoint]:
        """الحصول على جميع نقاط الحقن الفريدة"""
        seen = set()
        unique_points = []
        
        for point in self.injection_points:
            fingerprint = point.get_fingerprint()
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique_points.append(point)
        
        # ترتيب حسب الثقة
        unique_points.sort(key=lambda p: p.confidence, reverse=True)
        
        return unique_points
    
    def get_points_by_type(self, param_type: ParamType) -> List[InjectionPoint]:
        """الحصول على نقاط حقن حسب النوع"""
        return [p for p in self.injection_points if p.param_type == param_type]
    
    def get_points_by_method(self, method: str) -> List[InjectionPoint]:
        """الحصول على نقاط حقن حسب الـ HTTP method"""
        return [p for p in self.injection_points if p.method == method.upper()]
    
    def get_high_confidence_points(self, threshold: float = 0.8) -> List[InjectionPoint]:
        """الحصول على نقاط حقن ذات ثقة عالية"""
        return [p for p in self.injection_points if p.confidence >= threshold]
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على إحصائيات الاكتشاف"""
        return {
            'total_points': len(self.injection_points),
            'unique_points': len(self.get_all_points()),
            'unique_params': len(self.discovered_params),
            'discovered_urls': len(self.discovered_urls),
            'api_endpoints': len(self.api_endpoints),
            'by_source': self.source_stats,
            'by_type': {
                t.value: len(self.get_points_by_type(t)) 
                for t in ParamType
            }
        }
    
    def add_point(self, point: InjectionPoint):
        """إضافة نقطة حقن يدوياً"""
        self.injection_points.append(point)
        self.discovered_params.add(point.param_name)


# ==================== دوال مساعدة عامة ====================

def discover_all(base_url: str, html_content: str = None, 
                 js_content: str = None, api_response: Any = None) -> Dict[str, List[InjectionPoint]]:
    """دالة مساعدة لاكتشاف شامل"""
    discovery = InjectionPointDiscovery(base_url)
    all_points = []
    
    # اكتشاف من URL الأساسي
    all_points.extend(discovery.discover_from_url(base_url))
    
    # اكتشاف من HTML
    if html_content:
        all_points.extend(discovery.discover_from_html(base_url, html_content))
    
    # اكتشاف من JavaScript
    if js_content:
        all_points.extend(discovery.discover_from_javascript(base_url, js_content))
    
    # اكتشاف من API response
    if api_response:
        all_points.extend(discovery.discover_from_api_response(base_url, api_response))
    
    # تجميع النتائج
    return {
        'all': all_points,
        'by_type': {
            'query': discovery.get_points_by_type(ParamType.QUERY),
            'form': discovery.get_points_by_type(ParamType.FORM),
            'json': discovery.get_points_by_type(ParamType.JSON),
            'path': discovery.get_points_by_type(ParamType.PATH),
            'header': discovery.get_points_by_type(ParamType.HEADER),
        },
        'stats': discovery.get_stats()
    }

