#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
نظام الزحف الهجين المحسن - Smart Hybrid Crawler
يقوم بالزحف التقليدي + تنفيذ JavaScript + اكتشاف ذكي لنقاط الحقن
"""

import asyncio
import re
import time
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, unquote, quote
from collections import deque
import logging
from dataclasses import dataclass, field

from modules.base import BaseModule
from core.state import DiscoveredAsset, Finding, ScanState
from core.injection_discovery import InjectionPointDiscovery, InjectionPoint, ParamType

logger = logging.getLogger(__name__)

# محاولة استيراد Playwright للزحف الديناميكي
try:
    from playwright.async_api import async_playwright, Route, Page, Browser, Playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not available. Dynamic crawling disabled.")


@dataclass
class CrawlResult:
    """نتيجة زحف صفحة واحدة"""
    url: str
    status: int
    content: str
    content_type: str
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    api_calls: List[Dict] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    response_headers: Dict = field(default_factory=dict)
    response_time: float = 0.0


class SmartCrawler(BaseModule):
    """زاحف هجين ذكي مع اكتشاف تلقائي لنقاط الحقن"""
    
    MODULE_NAME = "crawler"
    MODULE_DESCRIPTION = "Smart hybrid crawler with automatic injection point discovery"
    
    # أنواع المحتوى المدعومة
    HTML_TYPES = {'text/html', 'application/xhtml+xml', 'application/xml'}
    JS_TYPES = {'application/javascript', 'text/javascript', 'application/x-javascript'}
    JSON_TYPES = {'application/json', 'application/json-seq', 'text/json'}
    
    # امتدادات الملفات المستبعدة
    EXCLUDED_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.bmp', '.webp',
        '.css', '.scss', '.less', '.sass',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z', '.bz2',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.exe', '.dll', '.bin', '.dmg', '.pkg', '.deb', '.rpm', '.apk',
    }
    
    # أنماط روابط خطيرة (تجنبها)
    DANGEROUS_PATHS = {
        '/logout', '/signout', '/exit', '/sign-off',
        '/delete', '/remove', '/drop', '/destroy',
        '/unsubscribe', '/cancel',
        '/admin/delete', '/admin/remove',
        '/api/delete', '/api/remove',
    }
    
    def __init__(self, config, state, http_client, ai_analyzer=None):
        super().__init__(config, state, http_client, ai_analyzer)
        
        # إعدادات الهدف
        self.target = config.get('target')
        self.parsed_target = urlparse(self.target)
        self.base_url = f"{self.parsed_target.scheme}://{self.parsed_target.netloc}"
        self.base_domain = self.parsed_target.netloc
        
        # إعدادات الزحف
        self.max_depth = config.get('crawler.max_depth', 3)
        self.max_pages = config.get('crawler.max_pages', 100)
        self.max_concurrent = config.get('crawler.max_concurrent', 10)
        self.request_timeout = config.get('scan.timeout', 30)
        self.use_dynamic = config.get('crawler.dynamic', True) and PLAYWRIGHT_AVAILABLE
        self.respect_robots = config.get('crawler.respect_robots', True)
        
        # أدوات الاكتشاف
        self.injection_discovery = InjectionPointDiscovery(self.base_url)
        
        # تخزين الزحف
        self.visited_urls: Set[str] = set()
        self.pending_urls: deque = deque()  # (url, depth, source)
        self.crawled_pages: Dict[str, CrawlResult] = {}
        self.discovered_apis: Set[str] = set()
        
        # Playwright
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.browser_context = None
        
        # إحصائيات
        self.stats = {
            'pages_crawled': 0,
            'static_crawled': 0,
            'dynamic_crawled': 0,
            'api_discovered': 0,
            'forms_found': 0,
            'injection_points': 0,
            'errors': 0,
        }
        
        logger.info(f"SmartCrawler initialized for {self.base_url}")
        logger.info(f"Settings: depth={self.max_depth}, max_pages={self.max_pages}, "
                   f"dynamic={self.use_dynamic}")
    
    # ==================== التهيئة ====================
    
    async def initialize(self):
        """تهيئة المتصفح للزحف الديناميكي"""
        if not self.use_dynamic or not PLAYWRIGHT_AVAILABLE:
            logger.info("Dynamic crawling disabled")
            return
        
        try:
            logger.info("Initializing Playwright browser...")
            self.playwright = await async_playwright().start()
            
            # إطلاق المتصفح مع إعدادات التخفي
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--disable-gpu',
                    '--window-size=1920,1080',
                ]
            )
            
            # إنشاء سياق المتصفح
            self.browser_context = await self.browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0.36',
                viewport={'width': 1920, 'height': 1080},
                locale='en-US',
                timezone_id='America/New_York',
                extra_http_headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,'
                             'image/avif,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                    'Cache-Control': 'max-age=0',
                }
            )
            
            logger.info("✅ Playwright browser initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Playwright: {e}")
            self.use_dynamic = False
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
    
    # ==================== التشغيل الرئيسي ====================
    
    async def run(self) -> Dict[str, Any]:
        """تنفيذ الزحف الذكي"""
        logger.info(f"{'='*60}")
        logger.info(f"Starting smart crawl for {self.base_url}")
        logger.info(f"{'='*60}")
        
        start_time = time.time()
        
        try:
            # المرحلة 1: الزحف الساكن السريع
            await self._phase_static_crawl()
            
            # المرحلة 2: الزحف الديناميكي (إذا كان مفعلاً)
            if self.use_dynamic and self.browser:
                await self._phase_dynamic_crawl()
            
            # المرحلة 3: تحليل وتوحيد النتائج
            await self._phase_analyze_results()
            
            # المرحلة 4: إضافة للـ state
            await self._phase_update_state()
            
        except Exception as e:
            logger.error(f"Crawl failed with error: {e}", exc_info=True)
            self.stats['errors'] += 1
        
        finally:
            await self.cleanup()
        
        duration = time.time() - start_time
        
        # طباعة ملخص
        logger.info(f"{'='*60}")
        logger.info(f"Crawl completed in {duration:.2f} seconds")
        logger.info(f"Stats: {self.stats}")
        logger.info(f"{'='*60}")
        
        return {
            'assets': self.assets,
            'findings': self.findings,
            'stats': {
                **self.stats,
                'duration': duration,
                'unique_urls': len(self.visited_urls),
                'injection_points_by_type': self._get_injection_stats(),
            },
            'crawled_pages': len(self.crawled_pages),
            'discovered_apis': list(self.discovered_apis),
        }
    
    # ==================== المرحلة 1: الزحف الساكن ====================
    
    async def _phase_static_crawl(self):
        """المرحلة الأولى: الزحف الساكن السريع"""
        logger.info("-" * 40)
        logger.info("Phase 1: Static Crawling")
        logger.info("-" * 40)
        
        # إضافة URL الهدف كبداية
        self._add_url_to_queue(self.target, 0, "target")
        
        # إنشاء semaphore للتحكم في التزامن
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        active_tasks = set()
        
        while (self.pending_urls or active_tasks) and len(self.visited_urls) < self.max_pages:
            # إضافة مهام جديدة حتى نصل للحد الأقصى المتزامن
            while len(active_tasks) < self.max_concurrent and self.pending_urls:
                url, depth, source = self.pending_urls.popleft()
                
                if url in self.visited_urls or depth > self.max_depth:
                    continue
                
                task = asyncio.create_task(
                    self._crawl_page_static(semaphore, url, depth, source)
                )
                active_tasks.add(task)
            
            if not active_tasks:
                break
            
            # انتظار أول مهمة تكتمل
            done, active_tasks = await asyncio.wait(
                active_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            
            # معالجة المهام المكتملة
            for task in done:
                try:
                    result = task.result()
                    if result:
                        self._process_crawl_result(result)
                except Exception as e:
                    logger.error(f"Static crawl task failed: {e}")
        
        logger.info(f"Static crawl complete: {self.stats['static_crawled']} pages")
    
    async def _crawl_page_static(self, semaphore: asyncio.Semaphore, url: str, 
                                  depth: int, source: str) -> Optional[CrawlResult]:
        """زحف صفحة واحدة بشكل ساكن"""
        async with semaphore:
            if url in self.visited_urls:
                return None
            
            self.visited_urls.add(url)
            
            try:
                logger.debug(f"[Static] Crawling: {url} (depth: {depth}, source: {source})")
                
                start_time = time.time()
                
                # تنفيذ الطلب
                response = await self.http_client.get(
                    url, 
                    timeout=self.request_timeout,
                    allow_redirects=True
                )
                
                response_time = time.time() - start_time
                
                self.state.increment_requests(success=True, url=url)
                
                # معالجة الرد
                content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
                content = await response.text()
                
                result = CrawlResult(
                    url=url,
                    status=response.status,
                    content=content,
                    content_type=content_type,
                    response_headers=dict(response.headers),
                    response_time=response_time
                )
                
                # استخراج البيانات حسب نوع المحتوى
                if self._is_html(content_type):
                    result.links = self._extract_links(url, content)
                    result.forms = self._extract_forms(url, content)
                    result.scripts = self._extract_scripts(content)
                    result.injection_points = self._analyze_injection_points(url, content, 'html')
                    
                elif self._is_javascript(content_type):
                    result.injection_points = self._analyze_injection_points(url, content, 'js')
                    
                elif self._is_json(content_type):
                    try:
                        import json
                        json_data = json.loads(content)
                        result.injection_points = self.injection_discovery.discover_from_api_response(
                            url, json_data
                        )
                    except:
                        pass
                
                # إضافة الروابط المكتشفة للطابور
                for link in result.links:
                    if self._should_crawl(link):
                        self._add_url_to_queue(link, depth + 1, f"link_from:{url}")
                
                self.stats['static_crawled'] += 1
                
                if len(self.visited_urls) % 10 == 0:
                    logger.info(f"Progress: {len(self.visited_urls)} pages crawled")
                
                return result
                
            except asyncio.TimeoutError:
                logger.warning(f"Timeout crawling {url}")
                self.state.increment_requests(success=False, url=url)
                self.stats['errors'] += 1
                return None
                
            except Exception as e:
                logger.debug(f"Failed to crawl {url}: {e}")
                self.state.increment_requests(success=False, url=url)
                self.stats['errors'] += 1
                return None
    
    # ==================== المرحلة 2: الزحف الديناميكي ====================
    
    async def _phase_dynamic_crawl(self):
        """المرحلة الثانية: الزحف الديناميكي مع Playwright"""
        if not self.browser or not self.browser_context:
            return
        
        logger.info("-" * 40)
        logger.info("Phase 2: Dynamic Crawling")
        logger.info("-" * 40)
        
        # اختيار الصفحات الأكثر أهمية للزحف الديناميكي
        important_pages = self._select_pages_for_dynamic_crawl()
        
        logger.info(f"Selected {len(important_pages)} pages for dynamic crawling")
        
        for page_url in important_pages:
            try:
                await self._crawl_page_dynamic(page_url)
            except Exception as e:
                logger.error(f"Dynamic crawl failed for {page_url}: {e}")
        
        logger.info(f"Dynamic crawl complete: {self.stats['dynamic_crawled']} pages")
    
    async def _crawl_page_dynamic(self, url: str):
        """زحف صفحة واحدة بشكل ديناميكي"""
        if url in self.visited_urls:
            # إعادة الزحف إذا كانت الصفحة مهمة
            pass
        
        logger.debug(f"[Dynamic] Crawling: {url}")
        
        page = None
        try:
            page = await self.browser_context.new_page()
            
            # اعتراض الشبكة
            api_calls = []
            
            async def handle_route(route: Route):
                request = route.request
                
                # تخزين API calls
                if self._is_api_call(request.url):
                    api_calls.append({
                        'url': request.url,
                        'method': request.method,
                        'headers': dict(request.headers),
                        'post_data': request.post_data,
                    })
                
                try:
                    await route.continue_()
                except:
                    pass
            
            await page.route("**/*", handle_route)
            
            # الانتقال للصفحة
            start_time = time.time()
            response = await page.goto(
                url, 
                wait_until='networkidle',
                timeout=self.request_timeout * 1000
            )
            response_time = time.time() - start_time
            
            if not response:
                return
            
            # الانتظار لتحميل المحتوى الديناميكي
            await asyncio.sleep(2)
            
            # التمرير لتحميل المحتوى الكسول
            await self._scroll_page(page)
            
            # الحصول على المحتوى النهائي
            final_html = await page.content()
            final_url = page.url
            
            # تنفيذ JavaScript للحصول على بيانات إضافية
            page_data = await self._extract_page_data(page)
            
            # إنشاء نتيجة الزحف
            result = CrawlResult(
                url=final_url,
                status=response.status,
                content=final_html,
                content_type='text/html',
                links=page_data.get('links', []),
                forms=page_data.get('forms', []),
                api_calls=api_calls,
                injection_points=[],
                response_time=response_time
            )
            
            # اكتشاف نقاط الحقن من المحتوى الديناميكي
            result.injection_points = self._analyze_injection_points(
                final_url, final_html, 'dynamic_html'
            )
            
            # إضافة API calls كنقاط حقن
            for api_call in api_calls:
                api_points = self.injection_discovery.discover_from_url(
                    api_call['url'], 'dynamic_api'
                )
                result.injection_points.extend(api_points)
                self.discovered_apis.add(api_call['url'])
            
            # معالجة النتيجة
            self._process_crawl_result(result)
            
            self.stats['dynamic_crawled'] += 1
            
        except Exception as e:
            logger.error(f"Dynamic crawl error for {url}: {e}")
            
        finally:
            if page:
                await page.close()
    
    async def _scroll_page(self, page: Page):
        """التمرير في الصفحة لتحميل المحتوى الكسول"""
        try:
            # التمرير التدريجي
            for i in range(3):
                await page.evaluate(f'window.scrollTo(0, document.body.scrollHeight * {i+1} / 3)')
                await asyncio.sleep(0.5)
            
            # العودة لأعلى الصفحة
            await page.evaluate('window.scrollTo(0, 0)')
            
        except Exception as e:
            logger.debug(f"Scroll failed: {e}")
    
    async def _extract_page_data(self, page: Page) -> Dict:
        """استخراج بيانات من الصفحة باستخدام JavaScript"""
        try:
            return await page.evaluate("""
                () => {
                    const data = {
                        links: [],
                        forms: [],
                        scripts: []
                    };
                    
                    // استخراج الروابط
                    document.querySelectorAll('a[href]').forEach(a => {
                        if (a.href && !a.href.startsWith('javascript:')) {
                            data.links.push({
                                href: a.href,
                                text: a.innerText.trim().substring(0, 50),
                                isVisible: a.offsetParent !== null
                            });
                        }
                    });
                    
                    // استخراج النماذج
                    document.querySelectorAll('form').forEach(form => {
                        const formData = {
                            action: form.action || window.location.href,
                            method: form.method || 'GET',
                            inputs: []
                        };
                        
                        form.querySelectorAll('input, select, textarea').forEach(input => {
                            if (input.name) {
                                formData.inputs.push({
                                    name: input.name,
                                    type: input.type || 'text',
                                    required: input.required
                                });
                            }
                        });
                        
                        if (formData.inputs.length > 0) {
                            data.forms.push(formData);
                        }
                    });
                    
                    // استخراج روابط JavaScript
                    document.querySelectorAll('script[src]').forEach(s => {
                        data.scripts.push(s.src);
                    });
                    
                    return data;
                }
            """)
        except Exception as e:
            logger.debug(f"Page data extraction failed: {e}")
            return {'links': [], 'forms': [], 'scripts': []}
    
    # ==================== المرحلة 3: تحليل النتائج ====================
    
    async def _phase_analyze_results(self):
        """المرحلة الثالثة: تحليل وتوحيد النتائج"""
        logger.info("-" * 40)
        logger.info("Phase 3: Analyzing Results")
        logger.info("-" * 40)
        
        # توحيد نقاط الحقن من جميع الصفحات
        all_points = []
        for result in self.crawled_pages.values():
            all_points.extend(result.injection_points)
        
        # إضافة للمحرك الرئيسي
        self.injection_discovery.injection_points = all_points
        
        # إحصائيات
        unique_points = self.injection_discovery.get_all_points()
        self.stats['injection_points'] = len(unique_points)
        self.stats['forms_found'] = sum(
            len(r.forms) for r in self.crawled_pages.values()
        )
        self.stats['api_discovered'] = len(self.discovered_apis)
        
        logger.info(f"Analysis complete:")
        logger.info(f"  - Unique injection points: {len(unique_points)}")
        logger.info(f"  - Forms discovered: {self.stats['forms_found']}")
        logger.info(f"  - API endpoints: {self.stats['api_discovered']}")
        
        # طباعة تفصيلية للـ injection points
        self._log_injection_points(unique_points)
    
    def _log_injection_points(self, points: List[InjectionPoint]):
        """طباعة تفاصيل نقاط الحقن"""
        if not points:
            logger.warning("No injection points discovered!")
            return
        
        # تجميع حسب النوع
        by_type = {}
        for p in points:
            pt = p.param_type.value
            by_type[pt] = by_type.get(pt, 0) + 1
        
        logger.info("Injection points by type:")
        for pt, count in sorted(by_type.items(), key=lambda x: -x[1]):
            logger.info(f"  - {pt}: {count}")
        
        # طباعة أمثلة
        logger.info("Sample injection points:")
        for p in points[:10]:
            logger.info(f"  [{p.param_type.value}] {p.method} {p.url}")
            logger.info(f"    Param: {p.param_name} (confidence: {p.confidence:.2f})")
    
    # ==================== المرحلة 4: تحديث State ====================
    
    async def _phase_update_state(self):
        """المرحلة الرابعة: تحديث state بالنتائج"""
        logger.info("-" * 40)
        logger.info("Phase 4: Updating State")
        logger.info("-" * 40)
        
        unique_points = self.injection_discovery.get_all_points()
        
        # تجميع حسب URL
        url_points: Dict[str, List[InjectionPoint]] = {}
        for point in unique_points:
            if point.url not in url_points:
                url_points[point.url] = []
            url_points[point.url].append(point)
        
        # إضافة endpoints للـ state
        endpoint_count = 0
        for url, points in url_points.items():
            # إنشاء asset للـ endpoint
            asset = DiscoveredAsset(
                type='endpoint',
                value=url,
                source='smart_crawler',
                confidence=max(p.confidence for p in points),
                metadata={
                    'methods': list(set(p.method for p in points)),
                    'param_count': len(points),
                    'params': [p.param_name for p in points],
                    'param_types': list(set(p.param_type.value for p in points)),
                    'sources': list(set(p.source for p in points)),
                }
            )
            self.state.add_asset(asset)
            self.add_asset(asset.to_dict())
            endpoint_count += 1
            
            # إضافة للـ discovered_endpoints
            self.state.discovered_endpoints.add(url)
            
            # إضافة parameters
            if url not in self.state.discovered_parameters:
                self.state.discovered_parameters[url] = set()
            for point in points:
                self.state.discovered_parameters[url].add(point.param_name)
        
        # إضافة API endpoints منفصلة
        for api_url in self.discovered_apis:
            if api_url not in url_points:
                asset = DiscoveredAsset(
                    type='api_endpoint',
                    value=api_url,
                    source='dynamic_crawl',
                    confidence=0.9,
                    metadata={'detected_by': 'network_interception'}
                )
                self.state.add_asset(asset)
                self.add_asset(asset.to_dict())
                self.state.discovered_endpoints.add(api_url)
        
        # تحديث الإحصائيات
        self.state.statistics.endpoints_discovered = len(self.state.discovered_endpoints)
        self.state.statistics.parameters_found = sum(
            len(params) for params in self.state.discovered_parameters.values()
        )
        
        logger.info(f"Added {endpoint_count} endpoints to state")
        logger.info(f"Total discovered endpoints: {len(self.state.discovered_endpoints)}")
        logger.info(f"Total discovered parameters: {self.state.statistics.parameters_found}")
    
    # ==================== معالجة النتائج ====================
    
    def _process_crawl_result(self, result: CrawlResult):
        """معالجة نتيجة زحف وتخزينها"""
        self.crawled_pages[result.url] = result
        
        # إضافة نقاط الحقن للمحرك الرئيسي
        self.injection_discovery.injection_points.extend(result.injection_points)
        
        # تسجيل الـ API calls
        for api_call in result.api_calls:
            self.discovered_apis.add(api_call['url'])
    
    def _add_url_to_queue(self, url: str, depth: int, source: str):
        """إضافة URL لطابور الزحف"""
        normalized = self._normalize_url(url)
        if not normalized:
            return
        
        if normalized in self.visited_urls:
            return
        
        # التحقق من عدم وجوده في الطابور
        for pending_url, _, _ in self.pending_urls:
            if pending_url == normalized:
                return
        
        self.pending_urls.append((normalized, depth, source))
    
    # ==================== استخراج البيانات ====================
    
    def _extract_links(self, base_url: str, content: str) -> List[str]:
        """استخراج روابط من HTML"""
        links = set()
        
        # أنماط استخراج الروابط
        patterns = [
            (r'href=["\']([^"\']+)["\']', 'href'),
            (r'src=["\']([^"\']+)["\']', 'src'),
            (r'action=["\']([^"\']*)["\']', 'form_action'),
            (r'url\s*\(\s*["\']([^"\']+)["\']', 'css_url'),
        ]
        
        for pattern, link_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                link = match.group(1).strip()
                
                # تنظيف الرابط
                if not link or link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    continue
                
                # تحويل لـ absolute URL
                absolute = urljoin(base_url, link)
                normalized = self._normalize_url(absolute)
                
                if normalized and self._should_crawl(normalized):
                    links.add(normalized)
        
        return list(links)
    
    def _extract_forms(self, base_url: str, content: str) -> List[Dict]:
        """استخراج نماذج HTML"""
        forms = []
        
        # Regex لاستخراج Forms
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        
        for match in re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE):
            form_attrs = match.group(1)
            form_content = match.group(2)
            
            # استخراج خصائص الـ form
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.I)
            
            action = action_match.group(1) if action_match else ''
            method = (method_match.group(1) if method_match else 'GET').upper()
            
            # تنظيف الـ action
            if not action or action == '#':
                action = base_url
            else:
                action = urljoin(base_url, action)
            
            # استخراج inputs
            inputs = []
            input_pattern = r'<(input|select|textarea)([^>]*)/?>'
            
            for input_match in re.finditer(input_pattern, form_content, re.I):
                tag_type = input_match.group(1).lower()
                input_attrs = input_match.group(2)
                
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_attrs, re.I)
                if not name_match:
                    continue
                
                name = name_match.group(1)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_attrs, re.I)
                input_type = type_match.group(1).lower() if type_match else 'text'
                
                # تجاهل الأزرار
                if input_type in ('submit', 'button', 'image', 'reset'):
                    continue
                
                required = 'required' in input_attrs.lower()
                
                inputs.append({
                    'name': name,
                    'type': input_type,
                    'tag': tag_type,
                    'required': required,
                })
            
            if inputs:
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                })
        
        return forms
    
    def _extract_scripts(self, content: str) -> List[str]:
        """استخراج روابط ملفات JavaScript"""
        scripts = []
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        
        for match in re.finditer(pattern, content, re.IGNORECASE):
            src = match.group(1)
            if src and not src.startswith(('http://', 'https://', '//')):
                scripts.append(src)
        
        return scripts
    
    def _analyze_injection_points(self, url: str, content: str, content_source: str) -> List[InjectionPoint]:
        """تحليل نقاط الحقن في المحتوى"""
        points = []
        
        # اكتشاف من URL
        points.extend(self.injection_discovery.discover_from_url(url, content_source))
        
        # اكتشاف من HTML
        if self._is_html_content(content):
            points.extend(self.injection_discovery.discover_from_html(url, content, content_source))
        
        # اكتشاف من JavaScript
        elif self._is_js_content(content):
            points.extend(self.injection_discovery.discover_from_javascript(url, content, content_source))
        
        return points
    
    # ==================== دوال مساعدة ====================
    
    def _normalize_url(self, url: str) -> Optional[str]:
        """تنظيف وتطبيع URL"""
        try:
            parsed = urlparse(url)
            
            # إزالة الـ fragment
            if '#' in url:
                url = url.split('#')[0]
            
            # إزالة الـ trailing slash (للـ paths فقط)
            if parsed.path and parsed.path != '/':
                url = url.rstrip('/')
            
            # إزالة الـ www إذا وجدت
            if parsed.netloc.startswith('www.'):
                netloc = parsed.netloc[4:]
                url = f"{parsed.scheme}://{netloc}{parsed.path}"
                if parsed.query:
                    url += f"?{parsed.query}"
            
            return url
            
        except Exception as e:
            logger.debug(f"URL normalization failed for {url}: {e}")
            return None
    
    def _should_crawl(self, url: str) -> bool:
        """التحقق مما إذا كان يجب زحف URL"""
        try:
            parsed = urlparse(url)
            
            # نفس الدومين فقط
            if parsed.netloc != self.base_domain:
                return False
            
            # تجاهل البروتوكولات الغير HTTP
            if parsed.scheme not in ('http', 'https'):
                return False
            
            # تجاهل الملفات الثابتة
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in self.EXCLUDED_EXTENSIONS):
                return False
            
            # تجاهل الروابط الخطيرة
            for dangerous in self.DANGEROUS_PATHS:
                if dangerous in path_lower:
                    logger.warning(f"Skipping dangerous path: {url}")
                    return False
            
            return True
            
        except Exception as e:
            return False
    
    def _is_html(self, content_type: str) -> bool:
        """التحقق إذا كان المحتوى HTML"""
        return any(ct in content_type.lower() for ct in self.HTML_TYPES)
    
    def _is_javascript(self, content_type: str) -> bool:
        """التحقق إذا كان المحتوى JavaScript"""
        return any(ct in content_type.lower() for ct in self.JS_TYPES)
    
    def _is_json(self, content_type: str) -> bool:
        """التحقق إذا كان المحتوى JSON"""
        return any(ct in content_type.lower() for ct in self.JSON_TYPES)
    
    def _is_html_content(self, content: str) -> bool:
        """التحقق من محتوى HTML بالنص"""
        return bool(re.search(r'<(!DOCTYPE|html|head|body|div|script|form)', content[:1000], re.I))
    
    def _is_js_content(self, content: str) -> bool:
        """التحقق من محتوى JavaScript بالنص"""
        indicators = ['function', 'var ', 'const ', 'let ', '=>', 'export', 'import']
        return any(ind in content[:500] for ind in indicators)
    
    def _is_api_call(self, url: str) -> bool:
        """التحقق إذا كان URL استدعاء API"""
        api_indicators = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/wp-json/']
        return any(ind in url.lower() for ind in api_indicators)
    
    def _select_pages_for_dynamic_crawl(self) -> List[str]:
        """اختيار الصفحات الأكثر أهمية للزحف الديناميكي"""
        candidates = []
        
        # أولوية للصفحات التي تحتوي على نماذج
        for url, result in self.crawled_pages.items():
            if result.forms:
                candidates.append((url, len(result.forms), 'has_forms'))
        
        # ثم الصفحات التي تحتوي على JavaScript كثير
        for url, result in self.crawled_pages.items():
            if len(result.scripts) > 3 and url not in [c[0] for c in candidates]:
                candidates.append((url, len(result.scripts), 'many_scripts'))
        
        # ترتيب حسب الأولوية واختيار الأفضل
        candidates.sort(key=lambda x: -x[1])
        
        # الحد الأقصى 10 صفحات للزحف الديناميكي
        return [url for url, _, _ in candidates[:10]]
    
    def _get_injection_stats(self) -> Dict[str, int]:
        """إحصائيات نقاط الحقن حسب النوع"""
        points = self.injection_discovery.get_all_points()
        stats = {}
        for p in points:
            pt = p.param_type.value
            stats[pt] = stats.get(pt, 0) + 1
        return stats
    
    # ==================== التنظيف ====================
    
    async def cleanup(self):
        """تنظيف الموارد"""
        logger.info("Cleaning up crawler resources...")
        
        try:
            if self.browser_context:
                await self.browser_context.close()
                self.browser_context = None
            
            if self.browser:
                await self.browser.close()
                self.browser = None
            
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
            
            logger.info("✅ Crawler cleanup complete")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
