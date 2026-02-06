#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Input Validation Module
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


async def validate_target(target: str) -> bool:
    """
    Validate target URL or domain
    
    Args:
        target: Target URL or domain
        
    Returns:
        True if valid
    """
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
    """
    Validate hostname format
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        True if valid
    """
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
    """
    Validate IP address
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_input(input_str: str) -> str:
    """
    Sanitize user input
    
    Args:
        input_str: Input string
        
    Returns:
        Sanitized string
    """
    # Remove null bytes
    sanitized = input_str.replace('\x00', '')
    
    # Remove control characters except newlines
    sanitized = ''.join(
        char for char in sanitized 
        if ord(char) >= 32 or char in '\n\r\t'
    )
    
    return sanitized.strip()


def validate_port(port: int) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number
        
    Returns:
        True if valid
    """
    return 1 <= port <= 65535


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain or None
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None
