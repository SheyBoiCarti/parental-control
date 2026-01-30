#!/bin/bash

# Parental Control Network Manager - Installation Script
# Supports Ubuntu/Debian and Raspberry Pi OS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       Parental Control Network Manager - Installer             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
else
    echo -e "${RED}Error: Cannot detect operating system${NC}"
    exit 1
fi

echo -e "${YELLOW}Detected OS: $OS $VERSION${NC}"
echo ""

# Get installation directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
INSTALL_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}Installation directory: $INSTALL_DIR${NC}"
echo ""

# Update package lists
echo -e "${GREEN}[1/8] Updating package lists...${NC}"
apt-get update

# Install system dependencies
echo -e "${GREEN}[2/8] Installing system dependencies...${NC}"
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    libpcap-dev \
    iptables \
    iproute2 \
    net-tools \
    curl \
    git

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.11"

echo -e "${YELLOW}Python version: $PYTHON_VERSION${NC}"

# Create virtual environment
echo -e "${GREEN}[3/8] Creating Python virtual environment...${NC}"
cd "$INSTALL_DIR/backend"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${GREEN}[4/8] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Create data directory
echo -e "${GREEN}[5/8] Creating data directory...${NC}"
mkdir -p "$INSTALL_DIR/data"
chown -R root:root "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/data"

# Check for Node.js (optional, for frontend development)
echo -e "${GREEN}[6/8] Checking Node.js for frontend...${NC}"
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${YELLOW}Node.js $NODE_VERSION is installed${NC}"

    # Build frontend
    echo "Building frontend..."
    cd "$INSTALL_DIR/frontend"
    npm install
    npm run build

    # Copy built files to serve statically
    mkdir -p "$INSTALL_DIR/backend/static"
    cp -r dist/* "$INSTALL_DIR/backend/static/"
else
    echo -e "${YELLOW}Node.js not found. Skipping frontend build.${NC}"
    echo -e "${YELLOW}Frontend can be built later with: cd frontend && npm install && npm run build${NC}"
fi

# Detect network interface
echo -e "${GREEN}[7/8] Detecting network interface...${NC}"
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_INTERFACE" ]; then
    DEFAULT_INTERFACE="eth0"
fi
echo -e "${YELLOW}Default network interface: $DEFAULT_INTERFACE${NC}"

# Create configuration
echo -e "${GREEN}[8/8] Creating configuration...${NC}"
cat > "$INSTALL_DIR/backend/.env" << EOF
# Network Configuration
NETWORK_INTERFACE=$DEFAULT_INTERFACE

# API Configuration
API_HOST=0.0.0.0
API_PORT=8080

# Authentication (generate hash with: python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())")
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=

# Logging
LOG_LEVEL=INFO
EOF

# Install systemd service
echo -e "${GREEN}Installing systemd service...${NC}"
cat > /etc/systemd/system/parental-control.service << EOF
[Unit]
Description=Parental Control Network Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/backend
Environment=PATH=$INSTALL_DIR/backend/venv/bin:/usr/bin:/bin
ExecStart=$INSTALL_DIR/backend/venv/bin/python main.py
Restart=on-failure
RestartSec=5

# Security
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   Installation Complete!                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  - Config file: $INSTALL_DIR/backend/.env"
echo "  - Data directory: $INSTALL_DIR/data"
echo "  - Network interface: $DEFAULT_INTERFACE"
echo ""
echo -e "${YELLOW}To set an admin password:${NC}"
echo "  1. Generate hash: python3 -c \"import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())\""
echo "  2. Add to $INSTALL_DIR/backend/.env as AUTH_PASSWORD_HASH"
echo ""
echo -e "${YELLOW}Commands:${NC}"
echo "  Start service:   sudo systemctl start parental-control"
echo "  Stop service:    sudo systemctl stop parental-control"
echo "  Enable on boot:  sudo systemctl enable parental-control"
echo "  View logs:       sudo journalctl -u parental-control -f"
echo ""
echo -e "${YELLOW}Access the web dashboard at:${NC}"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo -e "${GREEN}Start the service with: sudo systemctl start parental-control${NC}"
