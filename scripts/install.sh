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
    python3-dev \
    build-essential \
    libpcap-dev \
    libnetfilter-queue-dev \
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
pip install -r requirements.txt -c constraints.txt

# Create data directory
echo -e "${GREEN}[5/8] Creating data directory...${NC}"
mkdir -p "$INSTALL_DIR/data"
chown -R root:root "$INSTALL_DIR/data"
chmod 700 "$INSTALL_DIR/data"

# A normal installation includes the production dashboard.
echo -e "${GREEN}[6/8] Building the dashboard...${NC}"
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo -e "${RED}Node.js 22 and npm are required to build the dashboard.${NC}"
    exit 1
fi
if [ "$(node -p 'process.versions.node.split(".")[0]')" != "22" ]; then
    echo -e "${RED}Install Node.js 22 before running this installer.${NC}"
    exit 1
fi
cd "$INSTALL_DIR/frontend"
npm ci
npm run build
test -s dist/index.html
test -d dist/assets
mkdir -p "$INSTALL_DIR/backend/static"
cp -r dist/. "$INSTALL_DIR/backend/static/"
test -s "$INSTALL_DIR/backend/static/index.html"

# Detect network interface
echo -e "${GREEN}[7/8] Detecting network interface...${NC}"
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_INTERFACE" ]; then
    DEFAULT_INTERFACE="eth0"
fi
echo -e "${YELLOW}Default network interface: $DEFAULT_INTERFACE${NC}"

# Create configuration
echo -e "${GREEN}[8/8] Creating configuration...${NC}"
python "$INSTALL_DIR/scripts/configure_install.py" \
    "$INSTALL_DIR/backend/.env" "$INSTALL_DIR/backend/.env.example" "$DEFAULT_INTERFACE"

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
ExecStart="$INSTALL_DIR/backend/venv/bin/python" "$INSTALL_DIR/backend/main.py" --env-file "$INSTALL_DIR/backend/.env"
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
echo "  sudo $INSTALL_DIR/backend/venv/bin/python $INSTALL_DIR/backend/main.py --env-file $INSTALL_DIR/backend/.env --reset-password"
echo "  Existing credentials are preserved. This command explicitly resets them."
echo ""
echo -e "${YELLOW}Commands:${NC}"
echo "  Start service:   sudo systemctl start parental-control"
echo "  Stop service:    sudo systemctl stop parental-control"
echo "  Enable on boot:  sudo systemctl enable parental-control"
echo "  View logs:       sudo journalctl -u parental-control -f"
echo ""
echo -e "${YELLOW}Access the web dashboard at:${NC}"
echo "  New installs listen at http://127.0.0.1:8080 on the appliance. Existing listener settings are preserved."
echo "  Configure HTTPS_CERT_FILE, HTTPS_KEY_FILE, API_HOST and ALLOWED_ORIGINS for remote access."
echo ""
echo -e "${GREEN}Start the service with: sudo systemctl start parental-control${NC}"
