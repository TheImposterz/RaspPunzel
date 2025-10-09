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
- 🖥️ **Web Dashboard** - Real-time monitoring and control interface
- 🚀 **Headless Operation** - Auto-start services, no GUI needed

---

## 🛠️ Hardware Requirements

| Component | Specification |
|-----------|---------------|
| **Raspberry Pi** | Model 3B+ or 4 (2GB+ RAM recommended) |
| **MicroSD Card** | 64GB Class 10 minimum |
| **WiFi Adapters** | 2x USB adapters (Ralink RT5370/MT7601U recommended) |
| **Power Supply** | 5V 3A official power supply |

**Recommended WiFi Adapters:**
- ✅ **Ralink RT5370** (Alfa AWUS036NEH) - Excellent for AP mode
- ✅ **Ralink MT7601U** - Good for AP and monitoring
- ✅ **Realtek RTL8812AU** (Alfa AWUS036ACH) - Dual-band support
- ⚠️ Built-in Broadcom WiFi - Use for internet only, not for AP

---

## 🚀 Quick Start

### Step 1: Initial Setup

```bash
# 1. Clone repository
git clone https://github.com/TheImposterz/RaspPunzel.git
cd RaspPunzel

# 2. Detect WiFi adapters (IMPORTANT!)
sudo ./scripts/detect-wifi-adapters.sh

# Output will show detected adapters:
# [1] wlan0 (Broadcom) - Built-in → Internet
# [2] wlan1 (Ralink RT5370) - USB → Admin AP ✓
# [3] wlan2 (Ralink MT7601U) - USB → Pentest adapter

# 3. Copy the configuration snippet to config.sh
nano config.sh
```

### Step 2: Configure Before Installation

**Edit `config.sh` with your settings:**

```bash
nano config.sh
```

**Essential settings to configure:**

```bash
# =================================================================================================
# Ligolo-ng Configuration - YOUR PROXY SERVER
# =================================================================================================
LIGOLO_PROXY_HOST="vpn.yourdomain.com"  # Change to your VPS IP or domain
LIGOLO_PROXY_PORT="443"

# =================================================================================================
# WiFi Adapters - FROM detect-wifi-adapters.sh OUTPUT
# =================================================================================================
WLAN_INTERFACE_ADMIN="wlan1"            # Your Ralink adapter for AP
MAC_WLAN_ADMIN="00:c0:ca:xx:xx:xx"      # MAC from detection script

WLAN_INTERFACE_PENTEST="wlan2"          # Second adapter (optional)
MAC_WLAN_PENTEST="00:c0:ca:yy:yy:yy"

# =================================================================================================
# WiFi Credentials - FOR INTERNET CONNECTION
# =================================================================================================
WIFI_SSID="YourHomeWiFi"                # WiFi network to connect to
WIFI_PASSPHRASE="YourWiFiPassword"      # WiFi password

# =================================================================================================
# Admin Access Point - CHANGE DEFAULT PASSWORD!
# =================================================================================================
ADMIN_AP_SSID="RASPPUNZEL_ADMIN"
ADMIN_AP_PASSPHRASE="Change-Me-Now!"    # ⚠️ CHANGE THIS!
ADMIN_AP_HIDDEN="1"                     # 1=hidden (recommended)

# =================================================================================================
# Installation Options
# =================================================================================================
ENABLE_WEB_DASHBOARD="true"             # Web interface
ENABLE_PENTEST_TOOLS="true"             # WiFi pentest tools (~500MB)
ENABLE_HEADLESS_MODE="true"             # Remove GUI, auto-start
```

### Step 3: Run Installation

```bash
# Interactive installation (recommended)
sudo ./install.sh

# The installer will:
# ✓ Ask for confirmation on each component
# ✓ Install Ligolo-ng agent
# ✓ Configure network and services
# ✓ Install web dashboard (if enabled)
# ✓ Install pentest tools (if enabled)
# ✓ Convert to headless mode (if enabled)
# ✓ Configure auto-start services

# Reboot after installation
sudo reboot
```

### Step 4: Post-Installation

```bash
# After reboot, system will:
# ✓ Auto-login to console
# ✓ Auto-start all services
# ✓ Display system status

# Access web dashboard
http://<raspberry-pi-ip>:8080
# Default login: admin / rasppunzel
# ⚠️ CHANGE PASSWORD AFTER FIRST LOGIN!

# View installation summary
cat /root/RASPPUNZEL-INFO.txt
```

---

## 🎮 Operating Modes

### Mode 1: Network Pivot (Ligolo-ng)

Establish encrypted tunnel for remote network access.

**On Your Attack Machine (Proxy Server):**

```bash
# Option 1: Self-signed certificate (quick, testing)
sudo ./proxy -selfcert -laddr 0.0.0.0:443

# Option 2: Let's Encrypt certificate (production, recommended)
wget https://raw.githubusercontent.com/TheImposterz/RaspPunzel/main/scripts/certbot.sh
chmod +x certbot.sh
sudo ./certbot.sh yourdomain.com

# Start proxy with valid certificate
sudo ./proxy -certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
             -keyfile /etc/letsencrypt/live/yourdomain.com/privkey.pem \
             -laddr 0.0.0.0:443
```

**On RaspPunzel:**

The agent auto-connects at boot using configuration from `config.sh`.

```bash
# Check agent status
sudo systemctl status ligolo-agent

# View logs
sudo journalctl -u ligolo-agent -f

# Restart agent
sudo systemctl restart ligolo-agent
```

**Add routes on proxy server:**

```bash
# Add route for target network
sudo ip route add 192.168.1.0/24 dev ligolo

# Verify route
ip route show
```

### Mode 2: WiFi Hotspot

Hidden admin access point for on-site access.

**Auto-configured at installation:**
- SSID: From `ADMIN_AP_SSID` in config.sh (default: RASPPUNZEL_ADMIN)
- Password: From `ADMIN_AP_PASSPHRASE` (⚠️ change default!)
- IP: 13.37.0.1
- DHCP: 13.37.0.2 - 13.37.0.30
- Hidden: Yes (if `ADMIN_AP_HIDDEN="1"`)

**Connect to AP:**

```bash
# From your laptop/phone:
# 1. Scan for hidden networks
# 2. Connect to ADMIN_AP_SSID
# 3. Access dashboard: http://13.37.0.1:8080
```

**Service control:**

```bash
# Check AP status
sudo systemctl status hostapd
sudo systemctl status dnsmasq

# View connected clients
cat /var/lib/misc/dnsmasq.leases

# Or via web dashboard
http://13.37.0.1:8080 → WiFi AP tab
```

### Mode 3: WiFi Pentest

Wireless security testing suite.

**Pre-installed tools** (if `ENABLE_PENTEST_TOOLS="true"`):

**Basic Tools:**
- wifite, reaver, bully, mdk4, kismet
- hcxdumptool, hcxtools, cowpatty

**Advanced Frameworks:**
- Wifipumpkin3 - Rogue AP framework
- Wifiphisher - Evil twin attacks
- Fluxion - Social engineering
- EAPHammer - WPA2-Enterprise attacks
- Airgeddon - All-in-one WiFi tool

**Control via:**
- Web dashboard: Pentest Adapters tab
- Command line: Tools in `/usr/share/`

```bash
# Example: Wifite
sudo wifite

# Example: Airgeddon
cd /usr/share/airgeddon
sudo ./airgeddon.sh
```

---

## 🖥️ Web Dashboard

**Access:** `http://<pi-ip>:8080` or `http://13.37.0.1:8080` (via AP)

**Default Credentials:**
- Username: `admin`
- Password: `rasppunzel`
- ⚠️ **CHANGE PASSWORD AFTER FIRST LOGIN!**

**Dashboard Features:**

| Tab | Features |
|-----|----------|
| **🔗 Ligolo-ng** | Connection status, active routes, logs, restart |
| **📡 WiFi AP** | Connected clients, DHCP leases, AP control |
| **🎯 Pentest Adapters** | WiFi adapters, monitor mode, network scanning |
| **⚙️ System** | CPU/RAM/Disk usage, services status, uptime |

**Security:**
- Session timeout: 8 hours
- HTTPS support (with Certbot)
- Password change enforced on first login

---

## ⚙️ Configuration

### WiFi Adapter Detection

**ALWAYS run before installation:**

```bash
sudo ./scripts/detect-wifi-adapters.sh
```

This script will:
- ✅ Detect all wireless interfaces
- ✅ Identify chipsets and drivers
- ✅ Recommend best adapter for AP
- ✅ Generate config.sh snippet
- ✅ Check AP mode support

**Example output:**

```
[1] wlan0 (up)
    MAC:     dc:a6:32:xx:xx:xx
    Driver:  brcmfmac
    Chipset: Broadcom BCM43430
    Type:    built-in
    ✓ Supports AP mode

[2] wlan1 (down)
    MAC:     00:c0:ca:xx:xx:xx
    Driver:  rt2800usb
    Chipset: Ralink Technology, Corp. RT5370
    Type:    USB
    USB ID:  148f:5370
    ✓ Supports AP mode

Recommended for Admin AP: wlan1

Add to config.sh:
  WLAN_INTERFACE_ADMIN="wlan1"
  MAC_WLAN_ADMIN="00:c0:ca:xx:xx:xx"
```

### Main Configuration File

**All settings in one place:**

```bash
nano config.sh
```

**Configuration sections:**

```bash
# Ligolo-ng: Proxy server settings
LIGOLO_PROXY_HOST="your.vps.com"
LIGOLO_PROXY_PORT="443"
LIGOLO_IGNORE_CERT="false"          # true for self-signed

# Network: WiFi adapters (from detection script)
WLAN_INTERFACE_ADMIN="wlan1"
MAC_WLAN_ADMIN="00:c0:ca:xx:xx:xx"

# WiFi: Internet connection
WIFI_SSID="YourWiFi"
WIFI_PASSPHRASE="YourPassword"

# Admin AP: Access point settings
ADMIN_AP_SSID="RASPPUNZEL_ADMIN"
ADMIN_AP_PASSPHRASE="StrongPassword!"
ADMIN_AP_HIDDEN="1"
ADMIN_AP_IP="13.37.0.1"

# Installation: What to install
ENABLE_WEB_DASHBOARD="true"
ENABLE_PENTEST_TOOLS="true"
ENABLE_HEADLESS_MODE="true"
ENABLE_CERTBOT="false"

# Web Dashboard
WEB_PORT="8080"
WEB_USERNAME="admin"
WEB_PASSWORD="rasppunzel"           # Changed after first login
```

### Certificate Configuration (Proxy Server)

**For production deployments with valid SSL:**

```bash
# On your proxy server (VPS)
wget https://raw.githubusercontent.com/TheImposterz/RaspPunzel/main/scripts/certbot.sh
chmod +x certbot.sh
sudo ./certbot.sh yourdomain.com

# Script will:
# ✅ Install certbot
# ✅ Generate Let's Encrypt certificate
# ✅ Configure auto-renewal
# ✅ Set proper permissions

# Start proxy with certificate
sudo ./proxy -certfile /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
             -keyfile /etc/letsencrypt/live/yourdomain.com/privkey.pem \
             -laddr 0.0.0.0:443
```

**In config.sh on RaspPunzel:**

```bash
LIGOLO_PROXY_HOST="yourdomain.com"
LIGOLO_IGNORE_CERT="false"          # Validate certificate
```

**Certificate Setup Matrix:**

```
┌─────────────────────┬──────────────────────┬────────────────────┐
│ Proxy Setup         │ config.sh Setting    │ Connection Status  │
├─────────────────────┼──────────────────────┼────────────────────┤
│ -selfcert           │ IGNORE_CERT="true"   │ ✅ Works           │
│ -selfcert           │ IGNORE_CERT="false"  │ ❌ Fails           │
│ Let's Encrypt cert  │ IGNORE_CERT="true"   │ ✅ Works           │
│ Let's Encrypt cert  │ IGNORE_CERT="false"  │ ✅ Secure (best)   │
└─────────────────────┴──────────────────────┴────────────────────┘
```

---

## 🔧 Management Commands

### Service Control

```bash
# Start all services
sudo rasppunzel-start

# Stop all services
sudo rasppunzel-stop

# Interactive service manager
sudo rasppunzel-manager

# Individual services
sudo systemctl status ligolo-agent
sudo systemctl status rasppunzel-web
sudo systemctl status hostapd
sudo systemctl status dnsmasq
```

### Ligolo-ng Commands

```bash
# View connection status
sudo systemctl status ligolo-agent

# View live logs
sudo journalctl -u ligolo-agent -f

# Restart agent
sudo systemctl restart ligolo-agent

# Show current routes
ip route show | grep ligolo

# Test connectivity
ping <target-ip> -I ligolo
```

### Update Tools

```bash
# Update pentest tools
sudo ./scripts/update-pentest-tools.sh

# Update system packages
sudo apt update && sudo apt upgrade

# Update Ligolo-ng agent
sudo ./scripts/install-ligolo.sh
```

---

## 🐛 Troubleshooting

### WiFi Adapter Not Detected

```bash
# List USB devices
lsusb | grep -i ralink

# Check wireless interfaces
iw dev

# Run detection script
sudo ./scripts/detect-wifi-adapters.sh

# Check drivers
dmesg | grep -i "rt2800\|rtl88\|mt76"

# Verify udev rules
cat /etc/udev/rules.d/70-persistent-net.rules
```

### Ligolo Agent Won't Connect

```bash
# Check proxy reachability
ping <proxy-host>
nc -zv <proxy-host> 443

# View agent logs
sudo journalctl -u ligolo-agent -f

# Check certificate validation
grep IGNORE_CERT /etc/rasppunzel/ligolo.conf

# Test manual connection
/usr/local/bin/ligolo-agent -connect <proxy>:443 -ignore-cert

# Restart agent
sudo systemctl restart ligolo-agent
```

### Admin AP Not Working

```bash
# Check hostapd status
sudo systemctl status hostapd
sudo journalctl -u hostapd -f

# Verify interface
iw dev
iwconfig wlan1  # or your WLAN_INTERFACE_ADMIN

# Check NetworkManager is not managing AP interface
cat /etc/NetworkManager/conf.d/99-rasppunzel-ap.conf

# Test hostapd manually
sudo hostapd /etc/hostapd/hostapd.conf

# Verify dnsmasq
sudo systemctl status dnsmasq
```

### Web Dashboard Not Accessible

```bash
# Check service status
sudo systemctl status rasppunzel-web
sudo systemctl status nginx

# View logs
sudo journalctl -u rasppunzel-web -f
tail -f /var/log/nginx/rasppunzel-*.log

# Restart services
sudo systemctl restart rasppunzel-web
sudo systemctl restart nginx

# Test Flask directly
curl http://localhost:5000/api/status

# Check firewall
sudo iptables -L -n
```

### Internet Connection Lost

```bash
# Check network interfaces
ip addr show

# Verify NetworkManager
sudo systemctl status NetworkManager

# Check WiFi connection
nmcli device status
nmcli connection show

# Reconnect to WiFi
sudo nmcli device wifi connect "YourSSID" password "YourPassword"

# Check routes
ip route show
```

---

## 📁 Project Structure

```
RaspPunzel/
├── install.sh                      # Main installation script
├── config.sh                       # Configuration file (EDIT THIS!)
│
├── scripts/
│   ├── detect-wifi-adapters.sh     # WiFi adapter detection wizard
│   ├── install-ligolo.sh           # Ligolo-ng installation
│   ├── setup-network.sh            # Network configuration
│   ├── install-web-dashboard.sh    # Web dashboard installation
│   ├── install-pentest-tools.sh    # Pentest tools installation
│   ├── convert-to-headless.sh      # Headless mode conversion
│   ├── update-pentest-tools.sh     # Update all tools
│   ├── start-services.sh           # Start all services
│   ├── stop-services.sh            # Stop all services
│   └── certbot.sh                  # Certificate setup (proxy server)
│
├── config/
│   └── services/
│       ├── ligolo-agent.service    # Systemd service
│       ├── rasppunzel-web.service  # Web dashboard service
│       └── nginx-rasppunzel.conf   # Nginx configuration
│
└── web/
    ├── index.html                  # Login page
    ├── dashboard.html              # Main dashboard
    ├── change-password.html        # Password change page
    └── api/
        ├── app.py                  # Flask backend
        └── requirements.txt        # Python dependencies
```

---

## ⚠️ Legal Notice

**AUTHORIZED USE ONLY**

This tool is designed for **authorized security testing by qualified professionals**.

✅ **Required:**
- Written authorization from system owner
- Compliance with applicable laws (CFAA, GDPR, etc.)
- Ethical and responsible use
- Professional security testing context

❌ **Prohibited:**
- Unauthorized access to systems
- Illegal activities or criminal use
- Privacy violations
- Malicious intent

**Users are solely responsible for lawful use. Authors assume no liability for misuse.**

**By using this tool, you agree to:**
1. Obtain proper authorization before testing
2. Follow responsible disclosure practices
3. Comply with all applicable laws
4. Use only in legitimate security assessments

---

## 📄 License

GPL V3 License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **Ligolo-ng** - Network tunneling by [@nicocha30](https://github.com/nicocha30/ligolo-ng)
- **Kali Linux** - Base OS and tools by [Offensive Security](https://www.kali.org/)
- **Pi-PwnBox-RogueAP** - Original inspiration by [@koutto](https://github.com/koutto/pi-pwnbox-rogueap)
- **Raspberry Pi Foundation** - Hardware platform
- Open source security community

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/TheImposterz/RaspPunzel/issues)
- **Documentation:** [GitHub Wiki](https://github.com/TheImposterz/RaspPunzel/wiki)
- **Discussions:** [GitHub Discussions](https://github.com/TheImposterz/RaspPunzel/discussions)

---

## 🚀 Quick Reference

**Installation Workflow:**
```bash
1. sudo ./scripts/detect-wifi-adapters.sh  # Detect adapters
2. nano config.sh                          # Configure settings
3. sudo ./install.sh                       # Run installation
4. sudo reboot                             # Reboot system
5. http://<ip>:8080                        # Access dashboard
```

**Daily Operations:**
```bash
# Check status
sudo rasppunzel-manager

# View logs
sudo journalctl -u ligolo-agent -f

# Update tools
sudo ./scripts/update-pentest-tools.sh
```

**Emergency Recovery:**
```bash
# Restore GUI (if needed)
sudo rasppunzel-restore-gui.sh

# Reset to defaults
sudo ./install.sh  # Re-run installation
```

---

**For authorized security testing only** 🔒

*RaspPunzel v2.1 - Portable Pentest Platform*