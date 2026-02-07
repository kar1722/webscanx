#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


async def validate_target(target: str) -> bool:
    
    if not target:
        return False
    
    # Add protocol if missing
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    try:
        parsed = urlparse(target)
        
        # Validate scheme
        if parsed.scheme not in ['http', 'https']:
            logger.error(f"Invalid scheme: {parsed.scheme}")
            return False
        
        # Validate hostname
        if not parsed.hostname:
            logger.error("No hostname specified")
            return False
        
        # Check for valid hostname or IP
        if not is_valid_hostname(parsed.hostname) and not is_valid_ip(parsed.hostname):
            logger.error(f"Invalid hostname or IP: {parsed.hostname}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Target validation error: {e}")
        return False

def is_valid_hostname(hostname: str) -> bool:
   
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot if present
    hostname = hostname.rstrip('.')
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True

def is_valid_ip(ip: str) -> bool:
   
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def sanitize_input(input_str: str) -> str:
    
    # Remove null bytes
    sanitized = input_str.replace('\x00', '')
    
    # Remove control characters except newlines
    sanitized = ''.join(
        char for char in sanitized 
        if ord(char) >= 32 or char in '\n\r\t'
    )
    
    return sanitized.strip()

def validate_port(port: int) -> bool:
    
    return 1 <= port <= 65535

def extract_domain(url: str) -> Optional[str]:
    
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None
