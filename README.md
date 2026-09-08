# Parental Control Network Manager

A Linux-based parental-control and network-management tool with a web dashboard for device monitoring, website and application blocking, device blocking, and bandwidth limiting.

> **Status: Beta / experimental**
>
> The project has automated backend, frontend, browser, firewall, NFQUEUE, and Linux traffic-control tests. Real-network behavior still depends on the deployment topology, router, client device, and protocols being used.

## Features

- Discover devices on a local network using ARP scanning
- Monitor device traffic
- Block devices from accessing the network
- Block domains and supported applications
- Limit per-device upload and download bandwidth
- Inspect plain DNS and TLS SNI traffic
- Drop UDP/443 traffic to encourage TCP/TLS fallback
- View access logs and bandwidth statistics
- Manage devices and rules from a React dashboard
- Receive live updates through WebSockets
- Persist desired rules and recover enforcement state after restart

## How it works

The Linux host must be able to observe and forward traffic between managed devices and the gateway. The application uses ARP-based interception, Linux firewall rules, traffic control (`tc`), and packet inspection.

A typical test topology is:

```text
Test client ── Test LAN ── Parental Control host ── Test router ── Internet
```

Use a dedicated test network, spare router, or isolated VLAN. Do not experiment with ARP interception on a network you do not own or administer.

## Requirements

- Linux: Ubuntu/Debian or Raspberry Pi OS recommended
- Root or sudo access
- Python 3.11 or 3.12
- Node.js 22 and npm
- `iptables`
- `iproute2`
- `libnetfilter-queue`
- A suitable wired Ethernet connection is recommended

A Raspberry Pi 4 or similar Linux device may be suitable for small networks, but performance depends on traffic volume and inspection settings.

## Installation

### Quick installation

```bash
git clone https://github.com/SheyBoiCarti/parental-control.git
cd parental-control
sudo ./scripts/install.sh
```

The installer:

- Installs system dependencies
- Creates the backend virtual environment
- Installs locked Python dependencies
- Builds the production dashboard
- Creates the application configuration
- Installs the systemd service

The installer expects Node.js 22 and npm to already be installed.

### Manual installation

Install system dependencies:

```bash
sudo apt update
sudo apt install -y \
  python3 python3-pip python3-venv python3-dev \
  build-essential libpcap-dev libnetfilter-queue-dev \
  iptables iproute2
```

Set up the backend:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -c constraints.txt
cd ..
```

Build the dashboard:

```bash
cd frontend
npm ci
npm run build
mkdir -p ../backend/static
cp -r dist/. ../backend/static/
cd ..
```

Create the configuration:

```bash
cp backend/.env.example backend/.env
chmod 600 backend/.env
```

Edit `backend/.env` with the correct network interface and deployment settings.

## Configuration

Important settings include:

```env
DATA_DIR=
NETWORK_INTERFACE=eth0
GATEWAY_IP=
NETWORK_SUBNET=

API_HOST=127.0.0.1
API_PORT=8080

AUTH_USERNAME=admin
AUTH_PASSWORD_HASH=

ALLOWED_ORIGINS=
HTTPS_CERT_FILE=
HTTPS_KEY_FILE=

ALLOW_INSECURE_DEVELOPMENT=false
```

For remote dashboard access, configure HTTPS and set `ALLOWED_ORIGINS` to the exact dashboard origin.

For local development only, you may explicitly enable HTTP:

```env
ALLOW_INSECURE_DEVELOPMENT=true
ALLOWED_ORIGINS=http://127.0.0.1:8080
```

Do not expose an unauthenticated or insecure dashboard to an untrusted network.

## Set the administrator password

```bash
sudo ./backend/venv/bin/python \
  backend/main.py \
  --env-file backend/.env \
  --reset-password
```

Passwords are stored as hashes. Existing credentials persist across restarts and installer reruns.

## Running the service

Manual start:

```bash
sudo ./backend/venv/bin/python \
  backend/main.py \
  --env-file backend/.env \
  -i eth0
```

Using systemd:

```bash
sudo systemctl start parental-control
sudo systemctl enable parental-control
```

View logs:

```bash
sudo journalctl -u parental-control -f
```

## Dashboard

Open the configured dashboard origin and sign in with the administrator account.

The dashboard supports:

- Device discovery and status
- Device names and monitoring state
- Device blocking
- Domain and application rules
- Upload/download limits
- Access logs
- Bandwidth statistics
- Password changes
- Enforcement status and failures

## Testing a real device

Use a dedicated test client and isolated test LAN.

### Device discovery

Connect the test client to the test LAN and confirm that it appears in the dashboard with the correct IP and MAC address.

### Device blocking

From the client:

```bash
ping 1.1.1.1
curl https://example.com
```

Block the device in the dashboard and verify that connectivity fails. Unblock it and verify that connectivity returns.

### Domain blocking

Add a domain rule in the dashboard, then test from the client:

```bash
dig example.com
curl -v https://example.com
```

Use ordinary DNS while testing. DNS-over-HTTPS, VPNs, and cached browser content can change the result.

### Bandwidth limiting

Set an obvious upload/download limit, then measure traffic through the device:

```bash
iperf3 -c <test-server> -t 30
iperf3 -c <test-server> -R -t 30
```

Compare the result with the rule disabled. The measured speed should be close to the configured limit, subject to network overhead and topology.

## Supported application blocking

The built-in catalog includes signatures for applications such as:

- TikTok
- Instagram
- YouTube
- Snapchat
- Facebook
- Messenger
- WhatsApp
- X/Twitter
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

Application signatures are domain lists. Blocking is not guaranteed to cover every endpoint used by an application.

## Limitations

- Enforcement currently covers forwarded IPv4 traffic that the appliance can intercept.
- IPv6 traffic is not filtered.
- VPNs and proxies can bypass inspection.
- DNS-over-HTTPS and other encrypted DNS protocols can bypass DNS-based rules.
- Encrypted ClientHello can hide the requested hostname.
- Non-TLS protocols may not expose a domain name for inspection.
- UDP/443 is dropped for protected devices to encourage TCP/TLS fallback; applications that require QUIC may fail.
- Application signatures do not guarantee complete application blocking.
- Device enforcement may remain pending until a current IP address is discovered.
- Bandwidth counters are based on Linux `tc` counters and include bytes reported by the kernel classifier.
- ARP interception can be detected by network-security tools.
- Real behavior depends on the network topology, router, client device, and traffic protocols.

## Security considerations

- Run this software only on networks you own or administer.
- Use a strong administrator password.
- Prefer HTTPS for remote dashboard access.
- Keep `backend/.env` readable only by the service account.
- Use a dedicated test LAN before deploying to a production network.
- Review firewall and forwarding behavior before enabling enforcement.
- The service requires root privileges for network operations.

## Verification

Portable checks:

```bash
backend/venv/bin/python -m pytest backend/tests -q

cd frontend
npm ci
npm run lint
npm run test -- --run
npm run build
npm run test:e2e
```

Privileged Linux adapter checks run inside a disposable network namespace:

```bash
sudo --preserve-env=PATH,GITHUB_WORKSPACE \
  unshare --net --mount-proc \
  bash scripts/run-linux-integration.sh
```

The Linux integration suite exercises real traffic-control classes, counters, iptables ownership, NFQUEUE binding, packet injection, cleanup, and restart recovery.

## Troubleshooting

### Service won't start

```bash
sudo journalctl -u parental-control -f
ip link show
```

### No devices detected

```bash
ip addr show eth0
sudo arp-scan -l
```

### Blocking not working

```bash
sudo iptables -L -n
sudo tc qdisc show
```

## License

MIT License

## Disclaimer

This software is intended for legitimate parental-control and network-administration purposes. Use it responsibly and in compliance with applicable laws. The authors are not responsible for misuse or damage caused by this software.
