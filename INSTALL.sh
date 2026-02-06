#!/bin/bash
# WebScanX Installation Script for Kali Linux

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              WebScanX Installation Script                  ║"
echo "║              For Kali Linux / Debian Systems               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some features may require root privileges${NC}"
fi

# Check Python version
echo -e "${BLUE}[*] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo -e "${RED}[!] Python 3.8 or higher is required${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python version check passed: $PYTHON_VERSION${NC}"

# Update system packages
echo -e "${BLUE}[*] Updating system packages...${NC}"
sudo apt-get update -qq

# Install system dependencies
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
sudo apt-get install -y -qq \
    python3-pip \
    python3-dev \
    python3-venv \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    build-essential

# Install optional dependencies for PDF generation
echo -e "${BLUE}[*] Installing optional dependencies...${NC}"
sudo apt-get install -y -qq \
    libpango1.0-0 \
    libpango1.0-dev \
    libcairo2 \
    libcairo2-dev \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    2>/dev/null || echo -e "${YELLOW}[!] Optional dependencies skipped${NC}"

# Create virtual environment
echo -e "${BLUE}[*] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${BLUE}[*] Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${BLUE}[*] Upgrading pip...${NC}"
pip install --upgrade pip -q

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip install -r requirements.txt -q

# Make webscanx.py executable
echo -e "${BLUE}[*] Setting up executable...${NC}"
chmod +x webscanx.py

# Create reports directory
echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p reports
mkdir -p logs

# Create symlink for global access
echo -e "${BLUE}[*] Creating system link...${NC}"
if [ -d "/usr/local/bin" ]; then
    sudo ln -sf "$(pwd)/webscanx.py" /usr/local/bin/webscanx 2>/dev/null || \
        echo -e "${YELLOW}[!] Could not create system link (requires root)${NC}"
fi

# Verify installation
echo -e "${BLUE}[*] Verifying installation...${NC}"
python3 -c "import aiohttp; import yaml; import colorama" 2>/dev/null && \
    echo -e "${GREEN}[+] Dependencies verified${NC}" || \
    echo -e "${RED}[!] Dependency verification failed${NC}"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Installation Complete!                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}WebScanX has been successfully installed!${NC}"
echo ""
echo "Usage:"
echo "  ./webscanx.py -t https://example.com"
echo "  python3 webscanx.py -t https://example.com --mode standard"
echo ""
echo "Or with virtual environment activated:"
echo "  source venv/bin/activate"
echo "  python3 webscanx.py -t https://example.com"
echo ""
echo "For help:"
echo "  python3 webscanx.py --help"
echo ""
