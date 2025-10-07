#!/bin/bash

# =================================================================================================
# RaspPunzel - Install Ligolo-ng Agent
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default configuration
LIGOLO_VERSION="${LIGOLO_VERSION:-v0.8.2}"
LIGOLO_PROXY_HOST="${LIGOLO_PROXY_HOST:-192.168.1.100}"
LIGOLO_PROXY_PORT="${LIGOLO_PROXY_PORT:-11601}"
LIGOLO_IGNORE_CERT="${LIGOLO_IGNORE_CERT:-true}"
LIGOLO_RETRY_DELAY="${LIGOLO_RETRY_DELAY:-10}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        LIGOLO_ARCH="amd64"
        ;;
    aarch64|arm64)
        LIGOLO_ARCH="arm64"
        ;;
    armv7l|armv6l)
        LIGOLO_ARCH="armv7"
        ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Installing Ligolo-ng Agent${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}[+] Configuration:${NC}"
echo -e "    Version:     ${LIGOLO_VERSION}"
echo -e "    Architecture: ${LIGOLO_ARCH}"
echo -e "    Proxy Host:  ${LIGOLO_PROXY_HOST}"
echo -e "    Proxy Port:  ${LIGOLO_PROXY_PORT}"
echo ""

# Check if already installed
if [ -f "/usr/local/bin/ligolo-agent" ]; then
    CURRENT_VERSION=$(/usr/local/bin/ligolo-agent --version 2>&1 | grep -oP 'v\d+\.\d+' || echo "unknown")
    echo -e "${YELLOW}[!] Ligolo-ng agent already installed (${CURRENT_VERSION})${NC}"
    read -p "Do you want to reinstall? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[+] Keeping existing installation${NC}"
        exit 0
    fi
fi

# Download URL - Correct format without 'v' prefix in filename
LIGOLO_URL="https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_${LIGOLO_ARCH}.tar.gz"

echo -e "${YELLOW}[~] Downloading Ligolo-ng agent...${NC}"
echo -e "    URL: ${LIGOLO_URL}"

# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download with retries
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if wget --timeout=30 --tries=3 -q --show-progress "${LIGOLO_URL}" -O ligolo-agent.tar.gz; then
        echo -e "${GREEN}[+] Download successful${NC}"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            echo -e "${YELLOW}[!] Download failed, retrying ($RETRY_COUNT/$MAX_RETRIES)...${NC}"
            sleep 3
        else
            echo -e "${RED}[!] Download failed after $MAX_RETRIES attempts${NC}"
            echo -e "${RED}[!] Please check:${NC}"
            echo -e "${RED}    1. Internet connectivity${NC}"
            echo -e "${RED}    2. GitHub is accessible${NC}"
            echo -e "${RED}    3. Release version exists: ${LIGOLO_VERSION}${NC}"
            echo ""
            echo -e "${YELLOW}[~] Available versions at: https://github.com/nicocha30/ligolo-ng/releases${NC}"
            rm -rf "$TMP_DIR"
            exit 1
        fi
    fi
done

# Verify download
if [ ! -f "ligolo-agent.tar.gz" ] || [ ! -s "ligolo-agent.tar.gz" ]; then
    echo -e "${RED}[!] Downloaded file is missing or empty${NC}"
    rm -rf "$TMP_DIR"
    exit 1
fi

echo -e "${YELLOW}[~] Extracting archive...${NC}"
if ! tar -xzf ligolo-agent.tar.gz; then
    echo -e "${RED}[!] Failed to extract archive${NC}"
    echo -e "${RED}[!] The downloaded file might be corrupted${NC}"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Find the agent binary
AGENT_BINARY=$(find . -name "agent" -type f | head -n 1)

if [ -z "$AGENT_BINARY" ] || [ ! -f "$AGENT_BINARY" ]; then
    echo -e "${RED}[!] Agent binary not found in archive${NC}"
    echo -e "${RED}[!] Archive contents:${NC}"
    tar -tzf ligolo-agent.tar.gz
    rm -rf "$TMP_DIR"
    exit 1
fi

echo -e "${YELLOW}[~] Installing agent binary...${NC}"
install -m 0755 "$AGENT_BINARY" /usr/local/bin/ligolo-agent

# Verify installation
if [ ! -f "/usr/local/bin/ligolo-agent" ]; then
    echo -e "${RED}[!] Failed to install agent binary${NC}"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Cleanup
rm -rf "$TMP_DIR"

echo -e "${GREEN}[+] Ligolo-ng agent installed successfully${NC}"

# Create systemd service
echo -e "${YELLOW}[~] Creating systemd service...${NC}"

# Build agent command
AGENT_CMD="/usr/local/bin/ligolo-agent -connect ${LIGOLO_PROXY_HOST}:${LIGOLO_PROXY_PORT}"

if [ "$LIGOLO_IGNORE_CERT" = "true" ]; then
    AGENT_CMD="${AGENT_CMD} -ignore-cert"
fi

AGENT_CMD="${AGENT_CMD} -retry"

cat > /etc/systemd/system/ligolo-agent.service <<EOF
[Unit]
Description=Ligolo-ng Agent - Network Tunneling
Documentation=https://github.com/nicocha30/ligolo-ng
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${AGENT_CMD}
Restart=always
RestartSec=${LIGOLO_RETRY_DELAY}
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

# Set permissions
chmod 644 /etc/systemd/system/ligolo-agent.service

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}[+] Systemd service created${NC}"

# Enable service
echo -e "${YELLOW}[~] Enabling service to start at boot...${NC}"
systemctl enable ligolo-agent

echo -e "${GREEN}[+] Service enabled${NC}"

# Create management scripts
cat > /usr/local/bin/ligolo-status <<'EOF'
#!/bin/bash
echo "=== Ligolo-ng Agent Status ==="
systemctl status ligolo-agent --no-pager
echo ""
echo "=== Recent Logs ==="
journalctl -u ligolo-agent -n 20 --no-pager
EOF
chmod +x /usr/local/bin/ligolo-status

cat > /usr/local/bin/ligolo-restart <<'EOF'
#!/bin/bash
echo "Restarting Ligolo-ng agent..."
systemctl restart ligolo-agent
sleep 2
systemctl status ligolo-agent --no-pager
EOF
chmod +x /usr/local/bin/ligolo-restart

cat > /usr/local/bin/ligolo-logs <<'EOF'
#!/bin/bash
journalctl -u ligolo-agent -f
EOF
chmod +x /usr/local/bin/ligolo-logs

cat > /usr/local/bin/ligolo-config <<'EOF'
#!/bin/bash
echo "=== Ligolo-ng Configuration ==="
echo ""
systemctl cat ligolo-agent | grep ExecStart
echo ""
echo "Binary: $(which ligolo-agent)"
echo "Version: $(ligolo-agent --version 2>&1 || echo 'unknown')"
echo ""
echo "Service Status:"
systemctl is-enabled ligolo-agent
systemctl is-active ligolo-agent
EOF
chmod +x /usr/local/bin/ligolo-config

echo -e "${GREEN}[+] Management scripts created:${NC}"
echo -e "    ligolo-status   - Show status and recent logs"
echo -e "    ligolo-restart  - Restart the agent"
echo -e "    ligolo-logs     - Follow live logs"
echo -e "    ligolo-config   - Show configuration"
echo ""

# Test agent binary
echo -e "${YELLOW}[~] Testing agent binary...${NC}"
if /usr/local/bin/ligolo-agent --version >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Agent binary is working${NC}"
else
    echo -e "${RED}[!] Agent binary test failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Installation Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Agent Configuration:${NC}"
echo -e "  Binary:       /usr/local/bin/ligolo-agent"
echo -e "  Service:      ligolo-agent.service"
echo -e "  Connect to:   ${LIGOLO_PROXY_HOST}:${LIGOLO_PROXY_PORT}"
echo -e "  Auto-start:   Enabled"
echo -e "  Ignore Cert:  ${LIGOLO_IGNORE_CERT}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Start agent:   ${GREEN}systemctl start ligolo-agent${NC}"
echo -e "  2. Check status:  ${GREEN}ligolo-status${NC}"
echo -e "  3. View logs:     ${GREEN}ligolo-logs${NC}"
echo ""
echo -e "${YELLOW}Management:${NC}"
echo -e "  systemctl start ligolo-agent    # Start agent"
echo -e "  systemctl stop ligolo-agent     # Stop agent"
echo -e "  ligolo-restart                  # Restart agent"
echo -e "  ligolo-status                   # Check status"
echo -e "  ligolo-config                   # View config"
echo ""
echo -e "${YELLOW}Note:${NC} Make sure the Ligolo-ng proxy is running on ${LIGOLO_PROXY_HOST}:${LIGOLO_PROXY_PORT}"
echo ""