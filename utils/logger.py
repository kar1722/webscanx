#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from colorama import init, Fore, Style

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    
    COLORS = {
        'DEBUG': Fore.BLUE + Style.DIM,
        'INFO': Fore.CYAN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    TIME_FORMAT = "%H:%M:%S"
    LOG_FORMAT = "[%(asctime)s] [%(levelname)-7s] %(message)s"
    
    def format(self, record):

        color = self.COLORS.get(record.levelname, Style.RESET_ALL)
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        
        log_fmt = self.LOG_FORMAT
        date_fmt = self.TIME_FORMAT
        
        formatter = logging.Formatter(log_fmt, date_fmt)
        return formatter.format(record)

class SQLMapLikeFormatter(logging.Formatter):
    
    COLORS = {
        'DEBUG': '',
        'INFO': Fore.CYAN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def __init__(self, fmt=None, datefmt=None):
        """Initialize formatter with proper defaults"""
        if fmt is None:
            fmt = '[%(asctime)s] [%(levelname)-7s] %(message)s'
        if datefmt is None:
            datefmt = '%H:%M:%S'
        super().__init__(fmt, datefmt)
    
    def format(self, record):
        """Format log record with sqlmap style"""

        if record.levelno < logging.INFO:
            return ""
        
        # Ensure asctime is set
        record.asctime = self.formatTime(record, self.datefmt)
        
        level_color = self.COLORS.get(record.levelname, '')
        level_str = f"{level_color}{record.levelname}{Style.RESET_ALL}"
        
        message = record.getMessage()
        
        time_str = record.asctime.split()[1] if record.asctime and ' ' in record.asctime else record.asctime
        
        return f"[{time_str}] [{level_str:<7}] {message}"


def setup_logging(level: str = 'INFO', log_file: str = None, format_string: str = None, sqlmap_style: bool = True):
    
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper()))
    
    logger.handlers = []
    
    if sqlmap_style:
        formatter = SQLMapLikeFormatter(
            fmt='[%(asctime)s] [%(levelname)-7s] %(message)s',
            datefmt='%H:%M:%S'
        )
    else:
        formatter = ColoredFormatter()
    
    # handler للـ console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(lambda record: record.levelno >= logging.INFO)
    logger.addHandler(console_handler)
    
    # handler لملف السجل (إذا تم تحديده)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def create_payload_logger():
    
    payload_logger = logging.getLogger('payloads')
    payload_logger.setLevel(logging.INFO)
    payload_logger.propagate = False  # منع التكرار
    
    # handler للـ console فقط
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '[%(asctime)s] [INFO]     [%(module)-12s] testing \'%(payload_type)s\': %(payload)s',
        datefmt='%H:%M:%S'
    )
    handler.setFormatter(formatter)
    payload_logger.addHandler(handler)
    
    return payload_logger

def log_payload(module_name: str, payload_type: str, payload: str, target: str = "", extra_info: str = ""):
    
    logger = logging.getLogger('payloads')
    
    if len(payload) > 50:
        display_payload = payload[:47] + "..."
    else:
        display_payload = payload
    
    record = logging.LogRecord(
        name='payloads',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='',
        args=(),
        exc_info=None
    )
    
    record.module = module_name.upper()
    record.payload_type = payload_type
    record.payload = display_payload
    
    logger.handle(record)
    
    if target or extra_info:
        info_logger = logging.getLogger()
        if target:
            info_logger.info(f"target: {target}")
        if extra_info:
            info_logger.info(extra_info)
