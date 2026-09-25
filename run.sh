#!/bin/bash

# ===================================================
# GOT JOED Air-Gapped Linux Launcher - FULL OFFLINE
# Root-Level Execution -> Sudo Check -> Install -> Launch
# ===================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}  GOT JOED Air-Gapped Linux Launcher / Server${NC}"
echo -e "${GREEN}  FULL OFFLINE - Python/Nmap Auto-Installer${NC}"
echo -e "${GREEN}===================================================${NC}\n"

# ===================================================
# PATH CONFIGURATION
# ===================================================
# Ensure strict resolution of the SCANNER root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LINUX_DIR="$ROOT_DIR/Linux"
WHEELS_DIR="$LINUX_DIR/wheels"
BACKEND_DIR="$ROOT_DIR/backend"
VENV_DIR="$ROOT_DIR/venv"

VENV_PYTHON="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_DIR/bin/pip"
PYTHON_EXE=""

# ===================================================
# 1. CHECK PYTHON 3
# ===================================================
echo -e "[*] [1/5] Checking Python..."

if command -v python3 &> /dev/null; then
    PYTHON_EXE="python3"
    echo -e "${GREEN}[OK] Python found: $(python3 --version)${NC}"
else
    echo -e "${RED}[ERROR] Python 3 is not installed on this base system.${NC}"
    echo "Ubuntu natively includes Python. Please ensure base Python is present."
    exit 1
fi

# ===================================================
# 2. CHECK & INSTALL NMAP (Offline .deb)
# ===================================================
echo -e "[*] [2/5] Checking Nmap..."

if command -v nmap &> /dev/null; then
    echo -e "${GREEN}[OK] Nmap found in PATH${NC}"
else
    echo -e "${YELLOW}[WARN] Nmap not found, attempting offline installation...${NC}"
    
    # Check if we have .deb files in the Linux directory
    if ls "$LINUX_DIR/"*.deb 1> /dev/null 2>&1; then
        echo -e "${YELLOW}Please enter your sudo password to install Nmap offline:${NC}"
        sudo dpkg -i "$LINUX_DIR"/*.deb
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[SUCCESS] Nmap installed${NC}"
        else
            echo -e "${RED}[ERROR] Failed to install Nmap dependencies.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}[ERROR] No .deb packages found in $LINUX_DIR! Cannot install Nmap.${NC}"
        exit 1
    fi
fi

# ===================================================
# 3. VIRTUAL ENVIRONMENT
# ===================================================
echo -e "[*] [3/5] Checking venv in SCANNER folder..."

SKIP_PIP=false
if [ -f "$VENV_PYTHON" ]; then
    "$VENV_PYTHON" -c "import fastapi, uvicorn, nmap" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[FAST] Venv ready - skipping pip install${NC}"
        SKIP_PIP=true
    fi
fi

if [ "$SKIP_PIP" = false ]; then
    if [ ! -d "$VENV_DIR" ]; then
        echo "[*] Creating virtual environment..."
        $PYTHON_EXE -m venv "$VENV_DIR"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}[ERROR] Venv creation failed.${NC}"
            echo -e "${YELLOW}Note: Some Ubuntu distros require 'python3-venv' to be installed.${NC}"
            exit 1
        fi
    fi

    # ===================================================
    # 4. INSTALL WHEELS OFFLINE
    # ===================================================
    echo -e "[*] [4/5] Installing offline packages..."
    
    # Allow passing if either .whl or .tar.gz (for python-nmap) is present
    if ! ls "$WHEELS_DIR/"*.whl 1> /dev/null 2>&1 && ! ls "$WHEELS_DIR/"*.tar.gz 1> /dev/null 2>&1; then
        echo -e "${RED}[ERROR] wheels/ folder is empty or missing in $LINUX_DIR!${NC}"
        exit 1
    fi

    # Removed setuptools and wheel from this line to prevent offline "not found" errors
    "$VENV_PYTHON" -m pip install --no-index --find-links="$WHEELS_DIR" --upgrade pip --quiet --disable-pip-version-check
    
    "$VENV_PIP" install --no-index --find-links="$WHEELS_DIR" fastapi uvicorn python-nmap pydantic --quiet --disable-pip-version-check
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Packages installed successfully${NC}"
    else
        echo -e "${RED}[ERROR] Pip install failed. Check if all required packages are present.${NC}"
        exit 1
    fi

    # Verify installation
    "$VENV_PYTHON" -c "import fastapi, uvicorn, nmap" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Verification failed. Packages did not install correctly.${NC}"
        exit 1
    fi
fi

# ===================================================
# 5. LAUNCH BACKEND
# ===================================================
echo -e "[*] [5/5] Launching GOT JOED NIDS..."
echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}  SUCCESS - Engine Starting${NC}"
echo -e "${GREEN}  Keep this window OPEN${NC}"
echo -e "${GREEN}===================================================${NC}"

# Navigate to backend and start main.py
cd "$BACKEND_DIR"
"$VENV_PYTHON" main.py

echo "[INFO] Server stopped"