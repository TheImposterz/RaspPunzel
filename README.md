# 🚀 RaspPunzel

**Professional Penetration Testing Platform for Raspberry Pi**

A discrete and autonomous penetration testing implant designed for red team operations, security assessments, and authorized network evaluations.


![alt text](./img/archi.svg)


[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi-red.svg)](https://www.raspberrypi.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Hardware Requirements](#-hardware-requirements)
- [Operating Modes](#-operating-modes)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Web Dashboard](#-web-dashboard)
- [Management](#-management)
- [Troubleshooting](#-troubleshooting)
- [Legal Notice](#%EF%B8%8F-legal-notice)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

RaspPunzel transforms a Raspberry Pi into a powerful, portable penetration testing platform with three distinct operating modes:

1. **Network Pivot Mode** - Remote access via Ligolo-ng tunneling
2. **WiFi Hotspot Mode** - On-site wireless access point
3. **WiFi Pentest Mode** - Comprehensive wireless security testing

The platform is designed for professional security assessments, red team operations, and authorized penetration testing engagements.

---

## ✨ Features

### Core Capabilities

- 🌐 **Ligolo-ng Network Tunneling** - Secure remote pivot with encrypted connections
- 📡 **Dual WiFi Management** - Simultaneous admin AP and target interface
- 🔒 **WPA/WPA2/WPS Testing** - Complete wireless security assessment suite
- 🎯 **Evil Twin Attacks** - Rogue access point deployment
- 📊 **Web Dashboard** - Real-time monitoring and control interface
- 🔧 **Automated Setup** - One-command installation and configuration
- 📱 **Multi-Device Support** - Comprehensive WiFi adapter compatibility


## 🛠️ Hardware Requirements

### Required Components

| Component | Specification | Status |
|-----------|--------------|---------|
| **Raspberry Pi** | Model 3B+ or 4 (2GB+ RAM) | Required |
| **MicroSD Card** | 64GB Class 10 minimum | Required |
| **Power Supply** | 5V 3A USB-C (Pi 4) or Micro-USB (Pi 3) | Required |
| **WiFi Adapters** | 2x USB adapters with monitor mode | Required |

### Recommended WiFi Adapters

**Primary Adapters (Recommended):**
- **Alfa AWUS036NEH** - Ralink RT3070 (2.4GHz) - Excellent for pentesting
- **Alfa AWUS036ACH** - Realtek RTL8812AU (2.4/5GHz) - Dual-band
- **BrosTrend AC1L AC1200** - Suitable for AP mode

**Alternative Adapters:**
- TP-Link AC600 series
- Panda PAU09
- Any adapter with confirmed monitor mode support

### Optional Components

- **Enclosure** - Discrete case for field deployment
- **Power Bank** - 10,000mAh+ for portable operations
- **Cooling** - Heatsinks or small fan for extended operations
- **Ethernet Cable** - For wired network access

---

## 🎮 Operating Modes

### Mode 1: Remote Network Pivot

Establish encrypted tunneling via Ligolo-ng for remote network access.

**Use Cases:**
- Remote command and control
- Internal network pivoting
- Post-exploitation persistence
- Covert network access

**Features:**
- Encrypted agent-proxy communication
- Flexible proxy hosting (direct IP, ngrok, SSH forwarding)
- Port 443 (HTTPS) for firewall evasion
- Auto-reconnection on disconnect
- Multi-network routing

### Mode 2: On-Site WiFi Hotspot

Deploy a wireless access point for direct on-site access.

**Use Cases:**
- Maintenance access point
- Discrete wireless backdoor
- Local administration interface
- Team coordination network

**Features:**
- Hidden SSID option
- WPA2-PSK encryption
- DHCP server
- DNS configuration
- Client isolation

### Mode 3: WiFi Penetration Testing

Comprehensive wireless security assessment capabilities.

**Use Cases:**
- WPA/WPA2 security auditing
- WPS vulnerability testing
- Evil twin attack deployment
- Wireless reconnaissance
- Handshake capture and analysis

**Features:**
- Multiple attack vectors
- Automated tools integration
- Capture file management
- Real-time monitoring
- Multi-adapter coordination

---

## 📦 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/TheImposterz/RaspPunzel.git
cd RaspPunzel

# Run the installation script
sudo ./install.sh
```

The installation script will:
1. ✅ Update system packages
2. ✅ Install dependencies
3. ✅ Configure network interfaces
4. ✅ Install Ligolo-ng agent
5. ✅ Setup web dashboard
6. ✅ Install penetration testing tools
7. ✅ Configure systemd services
8. ✅ Create management scripts

### Installation Steps (Detailed)

#### 1. Prepare the Raspberry Pi

```bash
# Flash Kali Linux ARM image to microSD
# Download from: https://www.kali.org/get-kali/#kali-arm

# Boot the Pi and connect via SSH
ssh kali@<raspberry-pi-ip>
# Default password: kali

# Update the system
sudo apt update && sudo apt upgrade -y
```

#### 2. Clone and Install

```bash
# Clone the repository
git clone https://github.com/TheImposterz/RaspPunzel.git
cd RaspPunzel

# Make scripts executable
chmod +x install.sh
chmod +x scripts/*.sh

# Run installation
sudo ./install.sh
```

#### 3. Configure Ligolo-ng Agent

```bash
# Run the configuration wizard
sudo ./scripts/configure-ligolo.sh
```

The wizard will prompt for:
- **Proxy Host** - IP/domain of your proxy server (direct IP, ngrok URL, SSH forwarded address, etc.)
- **Proxy Port** - Default: 443 (HTTPS for firewall bypass)
- **Certificate Validation** - Ignore cert errors for self-signed certificates
- **Auto-Reconnect** - Enable automatic retry on disconnect

**Example Configurations:**

```bash
# Direct IP connection
Proxy Host: 203.0.113.10
Proxy Port: 443

# Ngrok tunnel
Proxy Host: 0.tcp.ngrok.io
Proxy Port: 12345

# SSH forwarding
Proxy Host: 127.0.0.1
Proxy Port: 11601
```

#### 4. Configure Network (WiFi Adapters)

```bash
# Setup network interfaces and access points
sudo ./scripts/setup-network.sh
```

This will configure:
- Built-in WiFi for internet connectivity
- USB adapter for admin access point
- USB adapter for penetration testing

#### 5. Install Web Dashboard

```bash
# Setup the web interface
sudo ./scripts/install-web-dashboard.sh
```

Access the dashboard at: `http://<raspberry-pi-ip>:8080`

---

## ⚙️ Configuration

### Configuration Files

```
RaspPunzel/
├── config/
│   ├── network/               # Network configuration templates
│   │   ├── dnsmasq.conf.template
│   │   ├── hostapd.conf.template
│   │   └── interfaces.template
│   ├── services/              # Service configurations
│   │   ├── nginx-rasppunzel.conf
│   │   └── ssh-config.template
│   └── systemd/               # Systemd service files
│       ├── rasppunzel-network.service
│       ├── rasppunzel-tower.service
│       └── rasppunzel-web.service
└── config.sh                  # Main configuration file
```

### Edit Configuration

```bash
# Edit main configuration
nano config.sh

# Edit Ligolo-ng configuration
nano /etc/rasppunzel/ligolo.conf

# Edit network configuration
nano config/network/interfaces.template
```

### WiFi Adapter Configuration

Identify your WiFi adapters:

```bash
# List network interfaces
ip link show

# List USB devices
lsusb

# Check wireless interfaces
iw dev
```

Update `config.sh` with your adapter MAC addresses:

```bash
# Example configuration
WLAN_INTERFACE_ADMIN="wlxaabbccddeeff"      # Admin AP adapter
WLAN_INTERFACE_ALFA_NEH="wlx00c0ca123456"   # Pentest adapter
```

---

## 🚀 Usage

### Starting the Proxy Server (On Your Attack Machine)

```bash
# Download Ligolo-ng proxy for your OS
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start proxy on port 443 (requires root)
sudo ./proxy -selfcert -laddr 0.0.0.0:443
```

**Alternative: Using Ngrok**

```bash
# Start ngrok tunnel
ngrok tcp 443

# Note the forwarding URL (e.g., 0.tcp.ngrok.io:12345)
# Configure agent with this URL using configure-ligolo.sh
```

### Starting RaspPunzel

```bash
# Start all services
sudo systemctl start ligolo-agent
sudo systemctl start rasppunzel-web
sudo systemctl start hostapd
sudo systemctl start dnsmasq

# Or use the management script
sudo ./scripts/start-services.sh


```

### Accessing the Dashboard

```bash
# Local access (on the Raspberry Pi)
http://localhost:8080

# Remote access (from your network)
http://<raspberry-pi-ip>:8080

# Default credentials (change after first login!)
Username: admin
Password: rasppunzel
```

### Network Pivot Workflow

**On Proxy Server:**
```bash
# Start proxy
sudo ./proxy -selfcert -laddr 0.0.0.0:443

# When agent connects, list sessions
session

# Select session
session 1

# List available networks
ifconfig

# Start tunnel
start

# Add routes on your machine
sudo ip route add 192.168.1.0/24 dev ligolo
sudo ip route add 10.0.0.0/24 dev ligolo
```

**On RaspPunzel:**
```bash
# Agent connects automatically
# View routing table
ligolo-show-routes

# Check agent status
ligolo-status

# View logs
ligolo-logs
```

### WiFi Hotspot Mode

```bash
# Start admin access point
sudo systemctl start hostapd
sudo systemctl start dnsmasq

# Check connected clients
sudo iw dev wlan1 station dump

# View DHCP leases
cat /var/lib/misc/dnsmasq.leases
```

### WiFi Penetration Testing

```bash
# Enable monitor mode
sudo airmon-ng start wlan2

# Scan for networks
sudo airodump-ng wlan2mon

# Launch Wifite (automated)
sudo wifite

# Launch Wifiphisher (evil twin)
cd /usr/share/wireless-tools/wifiphisher
sudo ./wifiphisher -aI wlan2 -jI wlan0

# Use web dashboard for tool management
```

---

## 🖥️ Web Dashboard

### Features

- **Real-Time Monitoring** - System status, CPU, memory, network
- **Service Control** - Start/stop/restart all services
- **Mode Switching** - Toggle between operating modes
- **Route Discovery** - Automatic network route detection
- **Log Viewing** - Live terminal output and system logs
- **Tool Launching** - Execute pentesting tools from GUI

### Dashboard Sections

**Status Bar:**
- Ligolo Agent status
- Admin AP status
- Rogue AP status
- Active routes count
- WiFi clients count
- System resources (CPU/Memory)

**Mode 1 - Network Pivot:**
- Ligolo controls (start/stop/restart)
- Active routes display
- Connection information
- Quick deploy commands

**Mode 2 - WiFi Hotspot:**
- Access point controls
- Connected clients list
- AP configuration details
- DHCP server status

**Mode 3 - WiFi Pentest:(Work in progress)**
- Tool launcher buttons
- Detected networks list
- Attack configuration
- Capture management

---

## 🔧 Management

### Management Scripts

```bash
# Service management
sudo ./scripts/start-services.sh      # Start all services
sudo ./scripts/stop-services.sh       # Stop all services
sudo ./scripts/service-manager.sh     # Interactive menu

# Ligolo management
ligolo-status                         # Check agent status
ligolo-restart                        # Restart agent
ligolo-logs                           # View live logs
ligolo-show-routes                    # Display routing table
configure-ligolo.sh                   # Reconfigure agent

# System management
sudo ./scripts/update-system.sh       # Update tools and system
```



### Systemd Services

```bash
# Ligolo Agent
sudo systemctl start ligolo-agent
sudo systemctl status ligolo-agent
sudo journalctl -u ligolo-agent -f

# Web Dashboard
sudo systemctl start rasppunzel-web
sudo systemctl status rasppunzel-web

# Network Services
sudo systemctl start rasppunzel-network
```

### Monitoring

```bash
# System resources
htop                # Interactive process viewer
iotop               # I/O monitoring
bmon                # Network bandwidth

# Network status
ip addr show        # Network interfaces
ip route show       # Routing table
iwconfig            # Wireless configuration

# Service logs
sudo journalctl -xe                    # All logs
sudo journalctl -u ligolo-agent -f     # Ligolo logs
sudo journalctl -u rasppunzel-web -f   # Web dashboard logs
```

---

## 🐛 Troubleshooting

### Ligolo Agent Won't Connect

**Check proxy reachability:**
```bash
# Test connection
nc -zv <proxy-host> 443

# Check DNS resolution
nslookup <proxy-host>

# View agent logs
ligolo-logs
```

**Solutions:**
- Ensure proxy is running on attack machine
- Verify firewall rules allow port 443
- Check network connectivity
- Reconfigure with: `sudo configure-ligolo.sh`

### WiFi Adapter Not Detected

**Check adapter:**
```bash
# List USB devices
lsusb

# Check wireless interfaces
iw dev

# Check driver loading
dmesg | grep -i rtl
```

**Solutions:**
- Reconnect USB adapter
- Install required drivers
- Check adapter compatibility
- Review `/etc/network/interfaces`

### Web Dashboard Not Accessible

**Check service:**
```bash
# Service status
sudo systemctl status rasppunzel-web

# Check port
sudo netstat -tulpn | grep 5000 #(python app.py)
sudo netstat -tulpn | grep 8080
# View logs
sudo journalctl -u rasppunzel-web -n 50
```

**Solutions:**
- Restart service: `sudo systemctl restart rasppunzel-web`
- Check firewall: `sudo ufw status`
- Fix app.py errors (check logs)
- Reinstall: `sudo ./scripts/install-web-dashboard.sh`

### Access Point Not Starting

**Check hostapd:**
```bash
# Service status
sudo systemctl status hostapd

# Test configuration
sudo hostapd -dd /etc/hostapd/hostapd.conf

# Check interface
ip link show <interface>
```

**Solutions:**
- Check interface name in configuration
- Ensure adapter supports AP mode
- Review `/etc/hostapd/hostapd.conf`
- Check for conflicting services

### Routes Not Showing

```bash
# Manual route check
ip route show

# Discover routes
sudo ./scripts/discover-routes.sh

# Add route manually
sudo ip route add 192.168.1.0/24 dev ligolo
```

### General Debugging

```bash
# Check all service statuses
sudo systemctl status ligolo-agent rasppunzel-web hostapd dnsmasq

# View all recent logs
sudo journalctl -xe --since "1 hour ago"

# Test network connectivity
ping -c 4 8.8.8.8
ping -c 4 google.com

# Check disk space
df -h

# Check memory
free -h
```

---

## ⚠️ Legal Notice

### AUTHORIZED USE ONLY

**This tool is designed exclusively for authorized security testing by qualified professionals.**

Users must:
- ✅ Obtain **explicit written authorization** before deployment
- ✅ Comply with all applicable **laws and regulations**
- ✅ Use only for **legitimate security testing** purposes
- ✅ Respect **privacy and data protection** requirements
- ✅ Document and report findings **responsibly**

### Legal Disclaimer

**Unauthorized access to computer systems is illegal.** Users assume full responsibility for lawful and ethical use. The authors and contributors:

- ❌ Do not endorse illegal activities
- ❌ Are not responsible for misuse of this software
- ❌ Provide no warranty or guarantee

### Ethical Guidelines

- **Scope**: Only test systems you own or have written permission to assess
- **Disclosure**: Report vulnerabilities responsibly to affected parties
- **Privacy**: Respect user data and privacy throughout testing
- **Damage**: Avoid causing harm or disruption to systems
- **Laws**: Follow all local, state, and federal laws

---

## 🤝 Contributing

Contributions are welcome from security professionals and researchers!

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines

- Test all changes thoroughly
- Follow existing code style
- Document new features
- Update README if needed
- Ensure compatibility with Raspberry Pi 3/4

### Reporting Issues

For bugs, vulnerabilities, or feature requests:
- Use GitHub Issues
- Provide detailed description
- Include system information
- Attach relevant logs

### Security Vulnerabilities

For security concerns:
- Use GitHub Security Advisories (private disclosure)
- Include detailed reproduction steps
- Allow reasonable time for response and fixes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Offensive Security** - Kali Linux
- **Raspberry Pi Foundation** - Hardware platform
- **Ligolo-ng Team** - Network tunneling
- **Open Source Security Community** - Tools and inspiration
- All tool developers and maintainers

---

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/TheImposterz/RaspPunzel/wiki)
- **Issues**: [GitHub Issues](https://github.com/TheImposterz/RaspPunzel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/TheImposterz/RaspPunzel/discussions)

---

**For authorized security testing only** 🔒

*RaspPunzel v2.0 - Professional Penetration Testing Platform*