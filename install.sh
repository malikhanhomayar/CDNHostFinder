#!/bin/bash
# ═══════════════════════════════════════════════════════
#  CDNHostFinder – Installation Script for Termux
#  Silent Hackers Team | @silent_ai_official
# ═══════════════════════════════════════════════════════

set -e

RED='\033[91m'
GREEN='\033[92m'
CYAN='\033[96m'
YELLOW='\033[93m'
RESET='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║       CDN HOST FINDER - INSTALLER            ║"
echo "║       Silent Hackers Team                    ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# Check if running in Termux
if [ -d "/data/data/com.termux" ]; then
    echo -e "${GREEN}[✓] Termux environment detected${RESET}"
else
    echo -e "${YELLOW}[!] Not running in Termux (continuing anyway)${RESET}"
fi

# Check Python
echo -e "${CYAN}[*] Checking Python installation...${RESET}"
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[✗] Python not found! Installing...${RESET}"
    pkg update -y && pkg install python -y
    PYTHON=python3
fi
echo -e "${GREEN}[✓] Python: $($PYTHON --version)${RESET}"

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${RESET}"
$PYTHON -m pip install --upgrade pip --quiet

# Install dependencies
echo -e "${CYAN}[*] Installing required packages...${RESET}"
$PYTHON -m pip install -r requirements.txt --quiet

# Verify installations
echo -e "${CYAN}[*] Verifying installations...${RESET}"
$PYTHON -c "import dns.resolver; print('  ✓ dnspython:', dns.__version__)" 2>/dev/null || \
    echo -e "${RED}  ✗ dnspython failed${RESET}"
$PYTHON -c "import requests; print('  ✓ requests:', requests.__version__)" 2>/dev/null || \
    echo -e "${RED}  ✗ requests failed${RESET}"

# Make script executable
chmod +x hostfinder.py

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║       INSTALLATION COMPLETE!                 ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Run the tool:"
echo -e "    ${CYAN}python3 hostfinder.py${RESET}"
echo ""
echo -e "  Or with domain:"
echo -e "    ${CYAN}python3 hostfinder.py -d example.com${RESET}"
echo ""
echo -e "  ${DIM}Results saved to: results.txt${RESET}"
echo ""