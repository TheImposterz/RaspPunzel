#!/bin/bash

# =================================================================================================
# RaspPunzel - Ligolo-ng Configuration Wizard
# =================================================================================================
# Interactive configuration for Ligolo-ng agent with secure connection setup
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE="/etc/rasppunzel/ligolo.conf"

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  RaspPunzel - Ligolo-ng Agent Configuration${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

# Create config directory
mkdir -p /etc/rasppunzel

# Load existing config if present
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}[~] Loading existing configuration...${NC}"
    source "$CONFIG_FILE"
    echo -e "${GREEN}[+] Current configuration loaded${NC}"
    echo ""
    echo -e "${CYAN}Current Settings:${NC}"
    echo -e "  Proxy Host: ${LIGOLO_PROXY_HOST:-Not set}"
    echo -e "  Proxy Port: ${LIGOLO_PROXY_PORT:-Not set}"
    echo -e "  Ignore Cert: ${LIGOLO_IGNORE_CERT:-Not set}"
    echo ""
    read -p "Do you want to reconfigure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[+] Keeping existing configuration${NC}"
        exit 0
    fi
fi

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              Ligolo-ng Agent Configuration                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# =================================================================================================
# Proxy Host Configuration
# =================================================================================================

echo -e "${YELLOW}[1/4] Proxy Host Configuration${NC}"
echo ""
echo -e "${CYAN}Enter the IP address or hostname of your Ligolo-ng proxy server.${NC}"
echo -e "${CYAN}This can be:${NC}"
echo -e "  • Direct IP address (e.g., 192.168.1.100)"
echo -e "  • Public IP/Domain (e.g., example.com, 203.0.113.5)"
echo -e "  • Ngrok URL (e.g., 0.tcp.ngrok.io)"
echo -e "  • SSH forwarded address (e.g., 127.0.0.1 if using SSH tunnel)"
echo ""

while true; do
    read -p "Proxy Host: " PROXY_HOST
    
    if [ -z "$PROXY_HOST" ]; then
        echo -e "${RED}[!] Proxy host cannot be empty${NC}"
        continue
    fi
    
    # Validate format (basic check)
    if [[ "$PROXY_HOST" =~ ^[a-zA-Z0-9][a-zA-Z0-9\.\-]+[a-zA-Z0-9]$ ]] || \
       [[ "$PROXY_HOST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "${GREEN}[+] Proxy host set to: ${PROXY_HOST}${NC}"
        break
    else
        echo -e "${RED}[!] Invalid hostname or IP format${NC}"
    fi
done

echo ""

# =================================================================================================
# Proxy Port Configuration
# =================================================================================================

echo -e "${YELLOW}[2/4] Proxy Port Configuration${NC}"
echo ""
echo -e "${CYAN}Enter the port where the Ligolo-ng proxy is listening.${NC}"
echo -e "${CYAN}Common ports:${NC}"
echo -e "  • 443  - HTTPS (Recommended, bypasses many firewalls)"
echo -e "  • 11601 - Default Ligolo-ng port"
echo -e "  • 8443 - Alternative HTTPS"
echo -e "  • Custom - Any port your proxy uses"
echo ""

while true; do
    read -p "Proxy Port [443]: " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}
    
    # Validate port number
    if [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [ "$PROXY_PORT" -ge 1 ] && [ "$PROXY_PORT" -le 65535 ]; then
        echo -e "${GREEN}[+] Proxy port set to: ${PROXY_PORT}${NC}"
        break
    else
        echo -e "${RED}[!] Invalid port number (must be 1-65535)${NC}"
    fi
done

echo ""

# =================================================================================================
# Certificate Validation
# =================================================================================================

echo -e "${YELLOW}[3/4] Certificate Validation${NC}"
echo ""
echo -e "${CYAN}Should the agent ignore SSL/TLS certificate errors?${NC}"
echo ""
echo -e "${GREEN}YES (Recommended for testing):${NC}"
echo -e "  • Use with self-signed certificates"
echo -e "  • Quick setup without certificate management"
echo -e "  • Still encrypted, but doesn't verify server identity"
echo ""
echo -e "${RED}NO (Production):${NC}"
echo -e "  • Use with valid SSL certificates"
echo -e "  • Better security, verifies server identity"
echo -e "  • Requires proper certificate setup on proxy"
echo ""

while true; do
    read -p "Ignore certificate errors? (Y/n): " IGNORE_CERT_CHOICE
    IGNORE_CERT_CHOICE=${IGNORE_CERT_CHOICE:-Y}
    
    case ${IGNORE_CERT_CHOICE^^} in
        Y|YES)
            IGNORE_CERT="true"
            echo -e "${GREEN}[+] Certificate validation disabled${NC}"
            break
            ;;
        N|NO)
            IGNORE_CERT="false"
            echo -e "${YELLOW}[!] Certificate validation enabled - ensure your proxy has valid certificates${NC}"
            break
            ;;
        *)
            echo -e "${RED}[!] Please answer Y or N${NC}"
            ;;
    esac
done

echo ""

# =================================================================================================
# Connection Options
# =================================================================================================

echo -e "${YELLOW}[4/4] Connection Options${NC}"
echo ""
echo -e "${CYAN}Additional connection settings:${NC}"
echo ""

read -p "Auto-reconnect on disconnect? (Y/n): " AUTO_RETRY
AUTO_RETRY=${AUTO_RETRY:-Y}
if [[ ${AUTO_RETRY^^} =~ ^Y|YES$ ]]; then
    RETRY="true"
    
    read -p "Retry delay in seconds [10]: " RETRY_DELAY
    RETRY_DELAY=${RETRY_DELAY:-10}
    echo -e "${GREEN}[+] Auto-retry enabled with ${RETRY_DELAY}s delay${NC}"
else
    RETRY="false"
    RETRY_DELAY="10"
    echo -e "${YELLOW}[+] Auto-retry disabled${NC}"
fi

echo ""

# =================================================================================================
# Test Connection (Optional)
# =================================================================================================

echo -e "${YELLOW}[~] Configuration Summary:${NC}"
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Connection Details                                          ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  Proxy Server:   ${NC}${PROXY_HOST}:${PROXY_PORT}"
echo -e "${CYAN}║  Ignore Cert:    ${NC}${IGNORE_CERT}"
echo -e "${CYAN}║  Auto-Retry:     ${NC}${RETRY}"
echo -e "${CYAN}║  Retry Delay:    ${NC}${RETRY_DELAY}s"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

read -p "Test connection before saving? (y/N): " TEST_CONN
if [[ ${TEST_CONN^^} =~ ^Y|YES$ ]]; then
    echo -e "${YELLOW}[~] Testing connection to ${PROXY_HOST}:${PROXY_PORT}...${NC}"
    
    if timeout 5 bash -c "echo > /dev/tcp/${PROXY_HOST}/${PROXY_PORT}" 2>/dev/null; then
        echo -e "${GREEN}[+] ✓ Connection successful!${NC}"
    else
        echo -e "${RED}[!] ✗ Cannot connect to ${PROXY_HOST}:${PROXY_PORT}${NC}"
        echo -e "${YELLOW}[!] This could mean:${NC}"
        echo -e "    • Proxy is not running"
        echo -e "    • Firewall blocking the connection"
        echo -e "    • Incorrect host/port"
        echo -e "    • Network not reachable"
        echo ""
        read -p "Continue anyway? (y/N): " CONTINUE
        if [[ ! ${CONTINUE^^} =~ ^Y|YES$ ]]; then
            echo -e "${RED}[!] Configuration cancelled${NC}"
            exit 1
        fi
    fi
fi

# =================================================================================================
# Save Configuration
# =================================================================================================

echo ""
echo -e "${YELLOW}[~] Saving configuration...${NC}"

cat > "$CONFIG_FILE" <<EOF
# RaspPunzel - Ligolo-ng Agent Configuration
# Generated: $(date)

# Proxy connection settings
LIGOLO_PROXY_HOST="${PROXY_HOST}"
LIGOLO_PROXY_PORT="${PROXY_PORT}"

# Security settings
LIGOLO_IGNORE_CERT="${IGNORE_CERT}"

# Connection behavior
LIGOLO_RETRY="${RETRY}"
LIGOLO_RETRY_DELAY="${RETRY_DELAY}"

# Agent settings
LIGOLO_VERSION="v0.8.2"
LIGOLO_BIND_ADDR="0.0.0.0"

# Export for systemd service
export LIGOLO_PROXY_HOST LIGOLO_PROXY_PORT LIGOLO_IGNORE_CERT LIGOLO_RETRY LIGOLO_RETRY_DELAY
EOF

chmod 600 "$CONFIG_FILE"
echo -e "${GREEN}[+] Configuration saved to ${CONFIG_FILE}${NC}"

# =================================================================================================
# Update Systemd Service
# =================================================================================================

echo -e "${YELLOW}[~] Updating systemd service...${NC}"

# Build agent command
AGENT_CMD="/usr/local/bin/ligolo-agent -connect ${PROXY_HOST}:${PROXY_PORT}"

if [ "$IGNORE_CERT" = "true" ]; then
    AGENT_CMD="${AGENT_CMD} -ignore-cert"
fi

if [ "$RETRY" = "true" ]; then
    AGENT_CMD="${AGENT_CMD} -retry"
fi

# Create/update systemd service
cat > /etc/systemd/system/ligolo-agent.service <<EOF
[Unit]
Description=Ligolo-ng Agent - Network Tunneling
Documentation=https://github.com/nicocha30/ligolo-ng
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/rasppunzel/ligolo.conf
ExecStart=${AGENT_CMD}
Restart=always
RestartSec=${RETRY_DELAY}
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=false
PrivateTmp=yes

# Network
BindsTo=network-online.target

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/ligolo-agent.service
systemctl daemon-reload

echo -e "${GREEN}[+] Systemd service updated${NC}"

# =================================================================================================
# Create Management Scripts
# =================================================================================================

echo -e "${YELLOW}[~] Creating management scripts...${NC}"

cat > /usr/local/bin/ligolo-config <<'EOF'
#!/bin/bash
# Show current Ligolo-ng configuration

CONFIG_FILE="/etc/rasppunzel/ligolo.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "No configuration found. Run: sudo configure-ligolo.sh"
    exit 1
fi

source "$CONFIG_FILE"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  RaspPunzel - Ligolo-ng Configuration                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Proxy Host:     $LIGOLO_PROXY_HOST"
echo "║  Proxy Port:     $LIGOLO_PROXY_PORT"
echo "║  Ignore Cert:    $LIGOLO_IGNORE_CERT"
echo "║  Auto-Retry:     $LIGOLO_RETRY"
echo "║  Retry Delay:    ${LIGOLO_RETRY_DELAY}s"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Connection String:"
echo "  ./agent -connect $LIGOLO_PROXY_HOST:$LIGOLO_PROXY_PORT -ignore-cert -retry"
echo ""
echo "Service Status:"
systemctl status ligolo-agent --no-pager | head -3
EOF

chmod +x /usr/local/bin/ligolo-config

cat > /usr/local/bin/ligolo-show-routes <<'EOF'
#!/bin/bash
# Show routing table for Ligolo networks

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Active Network Routes                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ip route show | while read line; do
    echo "  $line"
done

echo ""
echo "TUN Interfaces:"
ip link show type tun | grep -E "^[0-9]+:" | awk '{print "  " $2}'
EOF

chmod +x /usr/local/bin/ligolo-show-routes

echo -e "${GREEN}[+] Management scripts created${NC}"
echo -e "    • ligolo-config - Show configuration"
echo -e "    • ligolo-show-routes - Show routing table"

# =================================================================================================
# Completion
# =================================================================================================

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Configuration Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Next Steps:${NC}"
echo ""
echo -e "${YELLOW}1. On your attack machine, start the Ligolo-ng proxy:${NC}"
echo ""
echo -e "   ${GREEN}# Create TUN interface${NC}"
echo -e "   sudo ip tuntap add user \$(whoami) mode tun ligolo"
echo -e "   sudo ip link set ligolo up"
echo ""
echo -e "   ${GREEN}# Start proxy on port ${PROXY_PORT}${NC}"
if [ "$IGNORE_CERT" = "true" ]; then
    echo -e "   sudo ./proxy -selfcert -laddr 0.0.0.0:${PROXY_PORT}"
else
    echo -e "   sudo ./proxy -certfile cert.pem -keyfile key.pem -laddr 0.0.0.0:${PROXY_PORT}"
fi
echo ""
echo -e "${YELLOW}2. Start the Ligolo agent on this device:${NC}"
echo -e "   sudo systemctl start ligolo-agent"
echo ""
echo -e "${YELLOW}3. Check agent status:${NC}"
echo -e "   ligolo-status"
echo ""
echo -e "${YELLOW}4. View configuration:${NC}"
echo -e "   ligolo-config"
echo ""
echo -e "${YELLOW}5. View active routes:${NC}"
echo -e "   ligolo-show-routes"
echo ""

echo -e "${CYAN}Management Commands:${NC}"
echo -e "  ligolo-config        - Show current configuration"
echo -e "  ligolo-status        - Check agent status"
echo -e "  ligolo-restart       - Restart agent"
echo -e "  ligolo-show-routes   - Show routing table"
echo -e "  configure-ligolo.sh  - Reconfigure agent"
echo ""

read -p "Start Ligolo agent now? (y/N): " START_NOW
if [[ ${START_NOW^^} =~ ^Y|YES$ ]]; then
    echo -e "${YELLOW}[~] Starting Ligolo agent...${NC}"
    systemctl enable ligolo-agent
    systemctl start ligolo-agent
    sleep 2
    systemctl status ligolo-agent --no-pager
fi

echo ""
echo -e "${GREEN}Done!${NC}"