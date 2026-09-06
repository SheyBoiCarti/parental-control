# Parental Control Network Manager

A Linux-based network management tool for parental control that provides device monitoring, traffic inspection, app blocking, and bandwidth limiting through a web-based dashboard.

## Features

- **Device Discovery**: Automatic detection of all devices on your network using ARP scanning
- **Traffic Monitoring**: ARP spoofing to position the system as a man-in-the-middle for traffic inspection
- **App Blocking**: Block popular apps (TikTok, Instagram, YouTube, etc.) by inspecting DNS queries and TLS SNI
- **Domain Blocking**: Block specific domains or domain patterns
- **Bandwidth Limiting**: Per-device upload/download speed limits using Linux Traffic Control (tc)
- **Device Blocking**: Complete network access block using iptables
- **Real-time Dashboard**: Web-based interface with live updates via WebSocket
- **Access Logging**: Track which domains devices are accessing

## Requirements

### System Requirements

- Linux (Ubuntu/Debian or Raspberry Pi OS recommended)
- Root/sudo access
- Python 3.11 or 3.12
- Node.js 22 and npm (for building the dashboard)

### Hardware Recommendations

- Raspberry Pi 4 (2GB+ RAM) or similar
- Ethernet connection to the network
- Static IP address recommended

## Installation

### Quick Install

```bash
git clone https://github.com/your-repo/parental-control.git
cd parental-control
sudo ./scripts/install.sh
```

### Manual Installation

1. Install system dependencies:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev iptables iproute2
```

2. Create Python virtual environment:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -c constraints.txt
cd ..
```

3. Build and install the dashboard:
```bash
cd frontend
npm ci
npm run build
mkdir -p ../backend/static
cp -r dist/. ../backend/static/
cd ..
```

The backend serves `backend/static` independently of the working directory. Set
`STATIC_DIR` in the environment file to override it. For intentional API-only
development, set `API_ONLY=true`; dashboard routes then return 404. Missing
assets in dashboard mode return 503 with installation instructions.

4. Configure the application:
```bash
cp backend/.env.example backend/.env
# Edit .env with your network interface and settings
```

5. Run the application:
```bash
sudo ./backend/venv/bin/python backend/main.py -i eth0
```

## Configuration

Edit `backend/.env` to configure:

```env
# Network interface to monitor
NETWORK_INTERFACE=eth0

# API server settings
API_HOST=127.0.0.1
API_PORT=8080

# Authentication is required; saved credentials take precedence over bootstrap settings
AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=  # bcrypt hash

# Logging
LOG_LEVEL=INFO
```

### Setting a Password

Set the local administrator password using hidden input:

```bash
sudo ./backend/venv/bin/python backend/main.py --env-file backend/.env --reset-password
```

Saved credentials survive restarts and installer reruns. Run this command again
only when you intend to reset them. Browser password changes revoke existing sessions.

For remote browser access, configure `API_HOST`, `HTTPS_CERT_FILE`,
`HTTPS_KEY_FILE`, and `ALLOWED_ORIGINS` with your exact HTTPS dashboard origin.
For local HTTP development only, explicitly set `ALLOW_INSECURE_DEVELOPMENT=true`
and `ALLOWED_ORIGINS=http://127.0.0.1:8080`. An empty origin list does not allow
browser login. Keep `backend/.env` readable only by the service owner (`chmod 600`).

## Usage

### Starting the Service

```bash
# Manual start
sudo ./backend/venv/bin/python backend/main.py --env-file backend/.env -i eth0

# Using systemd
sudo systemctl start parental-control
sudo systemctl enable parental-control  # Start on boot
```

### Accessing the Dashboard

Open the HTTPS dashboard origin configured in `ALLOWED_ORIGINS`, or the loopback
HTTP URL after explicitly configuring local development. Log in as the configured
username (default `admin`) with the password you set. There is no passwordless login.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices |
| `/api/devices/{mac}` | GET | Get device details |
| `/api/devices/{mac}` | PATCH | Update device (name, block, monitor) |
| `/api/devices/{mac}/block` | POST/DELETE | Block/unblock device |
| `/api/devices/{mac}/monitor` | POST/DELETE | Start/stop monitoring |
| `/api/devices/{mac}/rules` | GET | List device rules |
| `/api/devices/{mac}/rules/bandwidth` | POST | Set bandwidth limit |
| `/api/devices/{mac}/rules/block-app` | POST | Block an app |
| `/api/devices/{mac}/rules/block-domain` | POST | Block a domain |
| `/api/stats/system` | GET | System statistics |
| `/ws` | WebSocket | Real-time updates |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              PARENTAL CONTROL SYSTEM                        │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard (React) ←→ REST API (FastAPI) ←→ WebSocket   │
├─────────────────────────────────────────────────────────────┤
│  Core Engine:                                               │
│  • Device Manager - ARP scanning, MAC tracking              │
│  • ARP Spoofer - MITM positioning via Scapy                 │
│  • Packet Analyzer - DNS/SNI inspection                     │
│  • Traffic Controller - Bandwidth limits via tc             │
│  • Content Blocker - App/domain blocking                    │
│  • Device Blocker - iptables MAC filtering                  │
├─────────────────────────────────────────────────────────────┤
│  SQLite Database                                            │
└─────────────────────────────────────────────────────────────┘
```

## Supported Apps for Blocking

- TikTok
- Instagram
- YouTube
- Snapchat
- Facebook
- Messenger
- WhatsApp
- Twitter/X
- Netflix
- Discord
- Twitch
- Spotify
- Reddit
- Telegram
- Roblox
- Fortnite
- Minecraft
- Zoom
- And more...

## Security Considerations

- This tool requires root privileges for network operations
- The dashboard should only be accessible on your local network
- Use a strong password for the admin account
- This tool should only be used on networks you own/administer
- ARP spoofing can be detected by network security tools

## Limitations

- **Encrypted DNS (DoH/DoT)**: Can bypass DNS-based blocking
  - Mitigation: Block known DoH provider IPs
- **VPNs**: Bypass all blocking when active
  - Mitigation: Can detect and block VPN protocols
- **HTTPS**: Cannot inspect encrypted content
  - Note: SNI inspection works without decryption
- **Static IP devices**: May need manual IP updates

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u parental-control -f

# Verify network interface
ip link show
```

### No devices detected

```bash
# Verify interface is correct
ip addr show eth0

# Test ARP scanning manually
sudo arp-scan -l
```

### Blocking not working

```bash
# Check iptables rules
sudo iptables -L -n

# Check tc configuration
sudo tc qdisc show
```

## License

MIT License

## Disclaimer

This software is intended for legitimate parental control and network administration purposes only. Use responsibly and in compliance with all applicable laws. The authors are not responsible for any misuse of this software.
