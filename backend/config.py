"""Configuration settings for the Parental Control system."""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "parental_control.db"

# Network settings
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
GATEWAY_IP = os.getenv("GATEWAY_IP", "")  # Auto-detected if empty
NETWORK_SUBNET = os.getenv("NETWORK_SUBNET", "")  # Auto-detected if empty

# ARP spoofing settings
ARP_SPOOF_INTERVAL = 2  # Seconds between ARP packets
DEVICE_SCAN_INTERVAL = 30  # Seconds between network scans

# Web server settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8080"))

# Authentication
AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD_HASH = os.getenv("AUTH_PASSWORD_HASH", "")  # bcrypt hash

# Traffic control settings
TC_ROOT_HANDLE = "1:"
TC_DEFAULT_CLASS = "9999"

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = DATA_DIR / "parental_control.log"

# App signatures file
APP_SIGNATURES_FILE = DATA_DIR / "app_signatures.json"
