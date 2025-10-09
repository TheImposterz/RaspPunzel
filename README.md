# 🍓 RaspPunzel

**Raspberry Pi Penetration Testing Platform**

Transform your Raspberry Pi into a portable pentest drop box with Ligolo-ng tunneling, WiFi hotspot capabilities, and wireless security testing tools.

![img](/img/archi.svg)

[![License: GPL V3](https://img.shields.io/badge/License-GPL3.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)

---

## 📋 What is RaspPunzel?

A discrete penetration testing implant that provides:

- 🔗 **Remote Network Pivot** - Encrypted tunneling via Ligolo-ng
- 📡 **WiFi Access Point** - Hidden admin hotspot for on-site access
- 🎯 **WiFi Pentesting** - Complete wireless security assessment toolkit

---

## 🛠️ Hardware Needed

| Component | Specification |
|-----------|---------------|
| **Raspberry Pi** | Model 3B+ or 4 (2GB+ RAM) |
| **MicroSD Card** | 64GB Class 10 minimum |
| **WiFi Adapters** | 2x USB adapters (Alfa AWUS036NEH/ACH recommended) |
| **Power Supply** | 5V 3A official power supply |

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/TheImposterz/RaspPunzel.git
cd RaspPunzel

# 2. Run installation
sudo ./install.sh

# 3. Configure Ligolo-ng agent
sudo ./scripts/configure-ligolo.sh

# 4. Access web dashboard
http://<raspberry-pi-ip>:8080
# Default login: admin / rasppunzel
```

---

## 🎮 Operating Modes

### Mode 1: Network Pivot (Ligolo-ng)

Establish encrypted tunnel for remote network access.

**Setting up the Proxy Server: ON ATTACKER MACHINE**

```bash
# On your attack machine (proxy server)

# Option 1: Self-signed certificate (quick, but less secure)
sudo ./proxy -selfcert -laddr 0.0.0.0:443

# Option 2: Valid SSL certificate (recommended for production)
# Download and run the certificate setup script
wget https://raw.githubusercontent.com/TheImposterz/RaspPunzel/main/scripts/certbot.sh
chmod +x certbot.sh
sudo ./certbot.sh

# The script will:
# - Install certbot
# - Generate Let's Encrypt certificate for your domain
# - Configure automatic renewal
# - Start proxy with valid certificate

# Start proxy with valid certificate
sudo ./proxy -certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
             -keyfile /etc/letsencrypt/live/yourdomain.com/privkey.pem \
             -laddr 0.0.0.0:443

# Agent auto-connects from RaspPunzel
# Add routes: sudo ip route add 192.168.1.0/24 dev ligolo
```

**Certificate Options:**

| Method | Use Case | Security | Setup Time |
|--------|----------|----------|------------|
| **Self-signed** (`-selfcert`) | Testing, lab environments | Low (certificate warnings) | Instant |
| **Let's Encrypt** (certbot) | Production, real engagements | High (trusted CA) | 5 minutes |

**Important Notes:**
- 🔒 **Self-signed certificates** require agent to ignore cert validation (`-ignore-cert`)
- ✅ **Let's Encrypt certificates** provide full TLS encryption without warnings
- 🌐 **Domain required** for Let's Encrypt (use a cheap domain or subdomain)
- 🔄 **Auto-renewal** is configured by certbot.sh script

**Agent Configuration:**

```bash
# On RaspPunzel, configure agent
sudo ./scripts/configure-ligolo.sh

# For self-signed certificates
Ignore certificate validation? [Y/n]: Y

# For Let's Encrypt certificates
Ignore certificate validation? [Y/n]: n
```

### Mode 2: WiFi Hotspot

Deploy hidden admin access point.

```bash
# Auto-starts at boot
# SSID: PWNBOX_ADMIN (hidden)
# Connect and access: http://10.0.0.1:8080
```

### Mode 3: WiFi Pentest

Wireless security testing suite.

```bash
# Pre-installed tools:
# - Wifite, Aircrack-ng, Wifiphisher
# - Fluxion, EAPHammer, Kismet
# Control via web dashboard
```

---

## 🖥️ Web Dashboard

**Access:** `http://<pi-ip>:8080`

**Features:**
- Real-time system monitoring
- Service control (start/stop/restart)
- Active routes display
- Connected WiFi clients
- Terminal output logs
- Pentest tool launcher

**Dashboard Tabs:**
- 🔗 **Ligolo-ng** - Tunnel management, routes, connection status
- 📡 **WiFi AP** - Hotspot control, client list, DHCP leases
- 🎯 **Pentest Adapters** - WiFi adapters, monitor mode, network scanning

---

## ⚙️ Configuration

### Main Configuration File

```bash
nano config.sh
```

Key settings:
- WiFi adapter MAC addresses
- Network interface names
- Default credentials
- Service settings

### Ligolo-ng Configuration

```bash
# Interactive wizard
sudo ./scripts/configure-ligolo.sh

# Or edit directly
nano /etc/rasppunzel/ligolo.conf
```

**Configuration wizard prompts:**

1. **Proxy Host:** Your proxy server IP/domain (e.g., `vpn.yourdomain.com` or `203.0.113.10`)
2. **Proxy Port:** 443 (default, recommended for firewall bypass)
3. **Certificate Validation:**
   - `Y` (Yes) - For self-signed certificates (use with `-selfcert`)
   - `n` (No) - For valid Let's Encrypt/CA certificates
4. **Auto-reconnect:** Enable automatic retry on connection loss

**Certificate Setup (Proxy Server):**

```bash
# Download certificate configuration script
wget https://raw.githubusercontent.com/TheImposterz/RaspPunzel/main/scripts/certbot.sh
chmod +x certbot.sh

# Run the script (requires domain name)
sudo ./certbot.sh yourdomain.com

# Script will:
# ✅ Install certbot and dependencies
# ✅ Generate Let's Encrypt certificate
# ✅ Configure automatic renewal (90 days)
# ✅ Set proper permissions
# ✅ Display proxy start command

# Start proxy with certificate
sudo ./proxy -certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
             -keyfile /etc/letsencrypt/live/yourdomain.com/privkey.pem \
             -laddr 0.0.0.0:443
```

**Certificate Validation Matrix:**

```
┌─────────────────────┬──────────────────────┬────────────────────┐
│ Proxy Setup         │ Agent Config         │ Connection Status  │
├─────────────────────┼──────────────────────┼────────────────────┤
│ -selfcert           │ -ignore-cert         │ ✅ Works           │
│ -selfcert           │ validate cert        │ ❌ Fails           │
│ Let's Encrypt cert  │ -ignore-cert         │ ✅ Works           │
│ Let's Encrypt cert  │ validate cert        │ ✅ Works (secure)  │
└─────────────────────┴──────────────────────┴────────────────────┘
```

**Recommended Setup for Production:**

1. Get a domain name (e.g., from Namecheap, Cloudflare)
2. Point domain to your proxy server IP
3. Run `certbot.sh` script on proxy server
4. Configure agent WITHOUT `-ignore-cert` flag
5. Enjoy full TLS encryption with trusted certificate

---

## 🔧 Management

### Service Control

```bash
# Start all services
sudo ./scripts/start-services.sh

# Stop all services
sudo ./scripts/stop-services.sh

# Service status
sudo systemctl status ligolo-agent
sudo systemctl status rasppunzel-web
sudo systemctl status hostapd
```

### Useful Commands

```bash
# Ligolo status
ligolo-status

# View logs
ligolo-logs
sudo journalctl -u ligolo-agent -f

# Restart agent
ligolo-restart

# Show routes
ligolo-show-routes

# Update system
sudo ./scripts/update-system.sh
```

---

## 🐛 Troubleshooting

### Ligolo won't connect

```bash
# Check proxy reachability
nc -zv <proxy-host> 443

# View logs
ligolo-logs

# Reconfigure
sudo ./scripts/configure-ligolo.sh
```

### WiFi adapter not detected

```bash
# List adapters
lsusb
iw dev

# Check drivers
dmesg | grep -i rtl
```

### Web dashboard not accessible

```bash
# Check service
sudo systemctl status rasppunzel-web

# Restart
sudo systemctl restart rasppunzel-web

# View logs
sudo journalctl -u rasppunzel-web -f
```

---

## 📁 Project Structure

```
RaspPunzel/
├── install.sh              # Main installation script
├── config.sh               # Configuration file
├── scripts/
│   ├── configure-ligolo.sh # Agent configuration wizard
│   ├── certbot.sh          # Certificate setup (for proxy server)
│   ├── start-services.sh
│   ├── stop-services.sh
│   └── update-system.sh
├── config/
│   ├── network/            # Network configs
│   ├── services/           # Service configs
│   └── systemd/            # Systemd units
└── web/
    ├── index.html          # Login page (hacker theme)
    ├── dashboard.html      # Main dashboard (matrix style)
    └── api/
        └── app.py          # Flask backend
```

---

## ⚠️ Legal Notice

**AUTHORIZED USE ONLY**

This tool is designed for **authorized security testing by qualified professionals**.

✅ **Required:**
- Written authorization from system owner
- Compliance with applicable laws
- Ethical and responsible use

❌ **Prohibited:**
- Unauthorized access to systems
- Illegal activities
- Privacy violations

**Users are solely responsible for lawful use. Authors assume no liability for misuse.**

---

## 📄 License

GPL V3 License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **Ligolo-ng** - Network tunneling ([nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng))
- **Kali Linux** - Base OS and tools ([Offensive Security](https://www.kali.org/))
- **Raspberry Pi Foundation** - Hardware platform
- Open source security community

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/TheImposterz/RaspPunzel/issues)
- **Documentation:** [GitHub Wiki](https://github.com/TheImposterz/RaspPunzel/wiki)
- **Discussions:** [GitHub Discussions](https://github.com/TheImposterz/RaspPunzel/discussions)

---

**For authorized security testing only** 🔒

*RaspPunzel v2.0*