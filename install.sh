#!/bin/bash
# ═══════════════════════════════════════════════════════
#  CDNHostFinder – Installation Script (Termux Safe)
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

# ── Detect environment ──────────────────────────────
IS_TERMUX=false
if [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
    echo -e "${GREEN}[✓] Termux environment detected${RESET}"
else
    echo -e "${YELLOW}[!] Standard Linux/macOS detected${RESET}"
fi

# ── Check/Install Python ────────────────────────────
echo -e "${CYAN}[*] Checking Python installation...${RESET}"
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo -e "${RED}[✗] Python not found! Installing...${RESET}"
    if [ "$IS_TERMUX" = true ]; then
        pkg update -y && pkg install python -y
    else
        echo -e "${RED}[✗] Please install Python 3 manually.${RESET}"
        exit 1
    fi
    PYTHON=python3
fi
echo -e "${GREEN}[✓] Python: $($PYTHON --version)${RESET}"

# ── Ensure pip is available (Termux-safe) ───────────
echo -e "${CYAN}[*] Checking pip...${RESET}"
if ! $PYTHON -m pip --version &>/dev/null; then
    if [ "$IS_TERMUX" = true ]; then
        echo -e "${YELLOW}[!] Installing python-pip via pkg...${RESET}"
        pkg install python-pip -y
    else
        echo -e "${RED}[✗] pip not found. Please install python3-pip.${RESET}"
        exit 1
    fi
fi
echo -e "${GREEN}[✓] pip: $($PYTHON -m pip --version)${RESET}"

# ── Install Python dependencies ─────────────────────
echo -e "${CYAN}[*] Installing required packages...${RESET}"
$PYTHON -m pip install dnspython requests urllib3 --quiet

# ── Verify installations ────────────────────────────
echo -e "${CYAN}[*] Verifying installations...${RESET}"
$PYTHON -c "import dns.resolver; print('  ✓ dnspython:', dns.__version__)" 2>/dev/null && \
    echo -e "${GREEN}  ✓ dnspython OK${RESET}" || \
    echo -e "${RED}  ✗ dnspython failed - try: pip install dnspython${RESET}"

$PYTHON -c "import requests; print('  ✓ requests:', requests.__version__)" 2>/dev/null && \
    echo -e "${GREEN}  ✓ requests OK${RESET}" || \
    echo -e "${RED}  ✗ requests failed - try: pip install requests${RESET}"

$PYTHON -c "import urllib3; print('  ✓ urllib3:', urllib3.__version__)" 2>/dev/null && \
    echo -e "${GREEN}  ✓ urllib3 OK${RESET}" || \
    echo -e "${RED}  ✗ urllib3 failed${RESET}"

# ── Make script executable ──────────────────────────
chmod +x hostfinder.py

# ── Done ────────────────────────────────────────────
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
