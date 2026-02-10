#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import random
import time
from typing import Dict, Optional
from dataclasses import dataclass
import logging 

logger = logging.getLogger(__name__)  

try:
    from playwright.async_api import async_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger = logging.getLogger(__name__)  

@dataclass
class HumanPattern:
    mouse_moves: int
    scrolls: int
    delays: list
    click_pattern: list

class StealthBrowser:
    
    def __init__(self, config):
        self.config = config
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._initialized = False
        
        self.human_patterns = {
            'fast': HumanPattern(3, 1, [0.1, 0.3], [True, False]),
            'normal': HumanPattern(5, 2, [0.3, 0.8], [True, True, False]),
            'slow': HumanPattern(8, 3, [0.5, 1.5], [True, True, True, False])
        }
        
        # User-Agents متنوعة
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        ]
        
        logger.info("Stealth browser initialized")
    
    async def initialize(self):
        
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning(" Playwright غير مثبت - تم تعطيل ميزة المتصفح التخفي")
            logger.info(" لتفعيل المتصفح التخفي: pip install playwright && playwright install")
            return False
        
        try:
            self.playwright = await async_playwright().start()
            
            browsers = ['chromium', 'firefox', 'webkit']
            selected_browser = random.choice(browsers)
            
            logger.info(f"تشغيل المتصفح: {selected_browser}")
            
            self.browser = await getattr(self.playwright, selected_browser).launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--disable-site-isolation-trials',
                ]
            )
            
            self.context = await self.browser.new_context(
                user_agent=random.choice(self.user_agents),
                viewport={'width': 1920, 'height': 1080},
                locale='en-US',
                timezone_id='America/New_York',
                permissions=['geolocation'],
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
            )
            
            await self.context.add_init_script("""
                // إخفاء WebDriver property
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
                
                // إخفاء Chrome runtime
                window.chrome = {
                    runtime: {}
                };
                
                // تعديل الـ Permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            
            self.page = await self.context.new_page()
            self._initialized = True
            
            logger.info("✅ تم تهيئة المتصفح المتخفي")
            return True
            
        except Exception as e:
            error_msg = str(e)
            logger.warning(f"⚠️ تعذر تهيئة المتصفح التخفي: {error_msg}")
            
            # Provide helpful instructions for common errors
            if "Host system is missing dependencies" in error_msg:
                logger.info("💡 لإصلاح هذا الخطأ، قم بتشغيل:")
                logger.info("   playwright install-deps")
                logger.info("   أو:")
                logger.info("   apt-get install libicu74 libjpeg-turbo8")
            elif "Executable doesn't exist" in error_msg:
                logger.info("💡 لإصلاح هذا الخطأ، قم بتشغيل:")
                logger.info("   playwright install")
            
            # Cleanup partial initialization
            await self.cleanup()
            return False
    
    async def simulate_human_behavior(self, pattern: str = 'normal'):
        if not self._initialized or not self.page:
            return

        human = self.human_patterns.get(pattern, self.human_patterns['normal'])
        
        for _ in range(human.mouse_moves):
            x = random.randint(0, 1920)
            y = random.randint(0, 1080)
            await self.page.mouse.move(x, y)
            await asyncio.sleep(random.choice(human.delays))
        
        for _ in range(human.scrolls):
            scroll_amount = random.randint(100, 500)
            scroll_direction = random.choice([-1, 1])
            await self.page.mouse.wheel(0, scroll_amount * scroll_direction)
            await asyncio.sleep(random.choice(human.delays))
        
        for should_click in human.click_pattern:
            if should_click:
                x = random.randint(100, 1820)
                y = random.randint(100, 980)
                await self.page.mouse.click(x, y)
                await asyncio.sleep(random.choice(human.delays))
    
    async def stealth_navigate(self, url: str):
        if not self._initialized or not self.page:
            logger.error("المتصفح غير مهيأ، لا يمكن التصفح")
            return None

        try:
            logger.info(f"🚀 التصفح المتخفي إلى: {url}")
            
            await self.page.goto(url, wait_until='networkidle')
            
            await self.simulate_human_behavior()
            
            await self.page.wait_for_load_state('networkidle')
            
            await self.simulate_human_behavior('fast')
            
            await self.page.evaluate("""
                // تفعيل بعض الأحداث الطبيعية
                window.dispatchEvent(new Event('focus'));
                window.dispatchEvent(new Event('blur'));
                
                // محاكاة writing
                const inputs = document.querySelectorAll('input[type="text"], textarea');
                if (inputs.length > 0) {
                    inputs[0].focus();
                    setTimeout(() => inputs[0].blur(), 100);
                }
            """)
            
            page_data = await self.collect_page_data()
            
            logger.info(f"✅ تم التصفح بنجاح: {url}")
            return page_data
            
        except Exception as e:
            logger.error(f"خطأ في التصفح المتخفي: {e}")
            return None
    
    async def collect_page_data(self) -> Dict:
        if not self._initialized or not self.page:
            return {}

        data = {}
        
        try:
            # HTML
            data['html'] = await self.page.content()
            
            data['cookies'] = await self.context.cookies()
            
            # Local Storage
            data['local_storage'] = await self.page.evaluate("""
                Object.keys(localStorage).reduce((obj, key) => {
                    obj[key] = localStorage.getItem(key);
                    return obj;
                }, {})
            """)
            
            # Session Storage
            data['session_storage'] = await self.page.evaluate("""
                Object.keys(sessionStorage).reduce((obj, key) => {
                    obj[key] = sessionStorage.getItem(key);
                    return obj;
                }, {})
            """)
            
            data['links'] = await self.page.evaluate("""
                Array.from(document.querySelectorAll('a')).map(a => ({
                    href: a.href,
                    text: a.textContent,
                    rel: a.rel
                }))
            """)
            
            data['forms'] = await self.page.evaluate("""
                Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
                        name: input.name,
                        type: input.type,
                        value: input.value
                    }))
                }))
            """)
            
            # JavaScript المتوفر
            data['scripts'] = await self.page.evaluate("""
                Array.from(document.querySelectorAll('script')).map(script => ({
                    src: script.src,
                    type: script.type
                }))
            """)
            
            logger.debug(f"تم جمع {len(data.get('links', []))} رابط و {len(data.get('forms', []))} نموذج")
            
        except Exception as e:
            logger.error(f"خطأ في جمع بيانات الصفحة: {e}")
        
        return data
    
    async def execute_javascript(self, script: str) -> Optional[str]:
        if not self._initialized or not self.page:
            logger.error("المتصفح غير مهيأ، لا يمكن تنفيذ JavaScript")
            return None

        try:
            result = await self.page.evaluate(script)
            return str(result) if result is not None else None
        except Exception as e:
            logger.error(f"خطأ في تنفيذ JavaScript: {e}")
            return None
    
    async def intercept_requests(self):
        if not self._initialized or not self.page:
            return

        await self.page.route("**/*", lambda route: asyncio.create_task(self.handle_route(route)))
    
    async def handle_route(self, route):
        if not self._initialized:
            await route.continue_()
            return

        request = route.request

        logger.debug(f"📨 طلب: {request.method} {request.url}")
        
        headers = request.headers
        
        headers['X-Requested-With'] = 'XMLHttpRequest'
        headers['X-Forwarded-Proto'] = 'https'
        
        await route.continue_(headers=headers)
    
    async def test_vulnerabilities_stealth(self, url: str, payloads: list):
        if not self._initialized:
            logger.error("المتصفح غير مهيأ")
            return []

        results = []
        
        for payload in payloads:
            try:
                await self.stealth_navigate(url)
                
                await self.page.evaluate(f"""
                    // البحث عن حقول الإدخال
                    const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
                    
                    if (inputs.length > 0) {{
                        // إدخال البايلود في الحقل الأول
                        inputs[0].value = {repr(payload)};
                        
                        // تفعيل events
                        inputs[0].dispatchEvent(new Event('input', {{ bubbles: true }}));
                        inputs[0].dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                """)
                
                await asyncio.sleep(random.uniform(1, 3))
                
                page_content = await self.page.content()
                
                if self.analyze_response(page_content, payload):
                    results.append({
                        'payload': payload,
                        'success': True,
                        'evidence': 'تم اكتشاف الثغرة'
                    })
                
                await asyncio.sleep(random.uniform(2, 5))
                
            except Exception as e:
                logger.error(f"خطأ في اختبار البايلود {payload}: {e}")
                results.append({
                    'payload': payload,
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def analyze_response(self, content: str, payload: str) -> bool:
        indicators = [
            'error' in content.lower(),
            'warning' in content.lower(),
            'mysql' in content.lower(),
            'sql' in content.lower(),
            'syntax' in content.lower(),
            'unexpected' in content.lower(),
            payload in content,
        ]
        
        return any(indicators)
    
    async def cleanup(self):
        try:
            if self.context:
                await self.context.close()
                self.context = None
            if self.browser:
                await self.browser.close()
                self.browser = None
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
            self._initialized = False
            logger.info("تم تنظيف موارد المتصفح")
        except Exception as e:
            logger.error(f"خطأ في التنظيف: {e}")
