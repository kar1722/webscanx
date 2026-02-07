#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import time
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    
    def __init__(self, rate: float, burst: int = 1):
        
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self._lock = asyncio.Lock()
        
        logger.debug(f"Rate limiter initialized: {rate} req/s, burst: {burst}")
    
    async def acquire(self):

        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst,
                self.tokens + elapsed * self.rate
            )
            self.last_update = now
            
            # Wait if no tokens available
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1
