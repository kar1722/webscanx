#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Banner Display Module
"""

from colorama import Fore, Style

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.WHITE}                                                                              {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}     ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗     {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}     ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝     {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}     ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝      {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}     ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗      {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}     ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗     {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}      ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝     {Fore.CYAN}║
{Fore.CYAN}║{Fore.WHITE}                                                                              {Fore.CYAN}║
{Fore.CYAN}║{Fore.YELLOW}              Advanced Web Application Security Testing Framework             {Fore.CYAN}║
{Fore.CYAN}║{Fore.GREEN}                         Designed for Kali Linux                              {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

MODES_INFO = f"""
{Fore.CYAN}Scan Modes:{Style.RESET_ALL}
  {Fore.GREEN}silent{Style.RESET_ALL}   - Stealthy reconnaissance with minimal footprint
  {Fore.GREEN}standard{Style.RESET_ALL} - Balanced scanning with good coverage
  {Fore.GREEN}deep{Style.RESET_ALL}     - In-depth analysis with correlation
  {Fore.GREEN}ai{Style.RESET_ALL}       - AI-guided intelligent scanning
"""


def display_banner(version: str):
    """Display WebScanX banner"""
    print(BANNER)
    print(f"{Fore.CYAN}                          Version: {Fore.WHITE}{version}")
    print(f"{Fore.CYAN}                          Author:  {Fore.WHITE}Alkashif X")
    print(f"{Fore.CYAN}                          License: {Fore.WHITE}MIT")
    print(Style.RESET_ALL)
