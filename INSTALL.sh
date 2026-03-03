#!/bin/bash

# WebScanX Installation Script
# For Kali Linux and Debian-based systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗     ║
║     ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝     ║
║     ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝      ║
║     ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗      ║
║     ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗     ║
║      ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝     ║
║                                                                              ║
║              Advanced Web Application Security Testing Framework             ║
║                         Installation Script v1.0.0                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[!] This script should not be run as root${NC}"
   echo -e "${YELLOW}[!] Please run as a regular user (sudo will be used when needed)${NC}"
   exit 1
fi

echo -e "${CYAN}[*] Starting WebScanX installation...${NC}\n"

# Check OS
echo -e "${CYAN}[*] Checking operating system...${NC}"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    echo -e "${GREEN}[+] Detected: $OS $VER${NC}"
else
    echo -e "${RED}[!] Cannot detect OS. This script is designed for Debian-based systems.${NC}"
    exit 1
fi

# Check Python version
echo -e "\n${CYAN}[*] Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [[ $PYTHON_MAJOR -ge 3 ]] && [[ $PYTHON_MINOR -ge 8 ]]; then
        echo -e "${GREEN}[+] Python $PYTHON_VERSION detected${NC}"
    else
        echo -e "${RED}[!] Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check pip
echo -e "\n${CYAN}[*] Checking pip...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[+] pip3 found${NC}"
else
    echo -e "${YELLOW}[!] pip3 not found. Installing...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# Install system dependencies
echo -e "\n${CYAN}[*] Installing system dependencies...${NC}"
echo -e "${YELLOW}[!] This may require sudo password${NC}"

sudo apt-get update

# Core dependencies
PACKAGES=(
    "python3-dev"
    "build-essential"
    "libssl-dev"
    "libffi-dev"
    "libxml2-dev"
    "libxslt1-dev"
    "zlib1g-dev"
    "git"
    "curl"
    "wget"
)

for package in "${PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $package"; then
        echo -e "${GREEN}[+] $package already installed${NC}"
    else
        echo -e "${CYAN}[*] Installing $package...${NC}"
        sudo apt-get install -y $package
    fi
done

# Install Python dependencies
echo -e "\n${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo -e "${GREEN}[+] Core dependencies installed${NC}"

# Optional: PDF generation support
echo -e "\n${CYAN}[*] Installing optional PDF generation support...${NC}"
read -p "Install PDF generation support (weasyprint)? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}[*] Installing PDF dependencies...${NC}"
    sudo apt-get install -y libpango1.0-0 libpangoft2-1.0-0 libffi-dev shared-mime-info
    pip3 install weasyprint
    echo -e "${GREEN}[+] PDF support installed${NC}"
else
    echo -e "${YELLOW}[!] Skipping PDF support${NC}"
fi

# Optional: Browser automation (Playwright)
echo -e "\n${CYAN}[*] Installing optional browser automation support...${NC}"
read -p "Install browser automation (Playwright) for stealth mode? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}[*] Installing Playwright...${NC}"
    pip3 install playwright
    python3 -m playwright install chromium firefox webkit
    python3 -m playwright install-deps
    echo -e "${GREEN}[+] Browser automation installed${NC}"
else
    echo -e "${YELLOW}[!] Skipping browser automation${NC}"
fi

# Create necessary directories
echo -e "\n${CYAN}[*] Creating directories...${NC}"
mkdir -p reports
mkdir -p logs
mkdir -p ~/.webscanx/ai_data
echo -e "${GREEN}[+] Directories created${NC}"

# Set permissions
echo -e "\n${CYAN}[*] Setting permissions...${NC}"
chmod +x webscanx.py
chmod +x INSTALL.sh
echo -e "${GREEN}[+] Permissions set${NC}"

# Create symlink (optional)
echo -e "\n${CYAN}[*] Creating system-wide command...${NC}"
read -p "Create system-wide 'webscanx' command? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    INSTALL_DIR=$(pwd)
    sudo ln -sf "$INSTALL_DIR/webscanx.py" /usr/local/bin/webscanx
    echo -e "${GREEN}[+] Command 'webscanx' created${NC}"
    echo -e "${GREEN}[+] You can now run 'webscanx' from anywhere${NC}"
else
    echo -e "${YELLOW}[!] Skipping system-wide command${NC}"
    echo -e "${YELLOW}[!] Run with: python3 webscanx.py${NC}"
fi

# Test installation
echo -e "\n${CYAN}[*] Testing installation...${NC}"
if python3 -c "import aiohttp, colorama, yaml; print('OK')" &> /dev/null; then
    echo -e "${GREEN}[+] Installation test passed${NC}"
else
    echo -e "${RED}[!] Installation test failed${NC}"
    echo -e "${RED}[!] Some dependencies may not be installed correctly${NC}"
    exit 1
fi

# Installation complete
echo -e "\n${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                     ✓ INSTALLATION COMPLETED SUCCESSFULLY                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${GREEN}# Basic scan${NC}"
echo -e "  python3 webscanx.py -t https://example.com"
echo -e ""
echo -e "  ${GREEN}# Silent mode (stealthy)${NC}"
echo -e "  python3 webscanx.py -t https://example.com --mode silent"
echo -e ""
echo -e "  ${GREEN}# Deep analysis with AI${NC}"
echo -e "  python3 webscanx.py -t https://example.com --mode deep --ai"
echo -e ""
echo -e "  ${GREEN}# Full scan with all reports${NC}"
echo -e "  python3 webscanx.py -t https://example.com --format json,html,pdf"
echo -e ""
echo -e "${CYAN}Documentation:${NC}"
echo -e "  README.md - Full documentation"
echo -e "  python3 webscanx.py --help - Command line options"
echo -e ""
echo -e "${YELLOW}⚠️  Legal Notice:${NC}"
echo -e "  Only scan systems you have permission to test."
echo -e "  Unauthorized scanning is illegal."
echo -e ""
echo -e "${GREEN}Happy Hacking! 🛡️${NC}\n"
