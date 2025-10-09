#!/bin/bash

# =================================================================================================
# RaspPunzel - Convert to Headless Server
# =================================================================================================
# Removes GUI, enables auto-login, and starts all services at boot
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}RaspPunzel Headless Conversion${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}This will:${NC}"
echo -e "  - Remove GUI (X11, Desktop Environment)"
echo -e "  - Configure auto-login to console"
echo -e "  - Enable all services at boot"
echo -e "  - Free up ~500MB RAM"
echo ""
echo -e "${RED}WARNING: This cannot be easily reversed!${NC}"
echo -e "${RED}You will only have SSH/Serial console access.${NC}"
echo ""
read -p "Continue? (yes/no): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${YELLOW}[~] Aborted${NC}"
    exit 0
fi

# =================================================================================================
# 1. Remove GUI packages
# =================================================================================================

echo -e "${YELLOW}[~] Removing GUI packages...${NC}"

# Stop display manager
systemctl stop lightdm 2>/dev/null || true
systemctl disable lightdm 2>/dev/null || true

# Remove X11 and desktop packages
apt-get remove -y --purge \
    xserver-xorg* \
    x11-common \
    lightdm* \
    xfce4* \
    gnome* \
    kde* \
    desktop-base \
    plymouth* \
    2>/dev/null || true

# Remove VNC (not needed without GUI)
systemctl stop vncserver 2>/dev/null || true
systemctl disable vncserver 2>/dev/null || true
apt-get remove -y --purge \
    tigervnc-* \
    x11vnc \
    realvnc-* \
    2>/dev/null || true

# Clean up
apt-get autoremove -y
apt-get autoclean

echo -e "${GREEN}[+] GUI removed${NC}"

# =================================================================================================
# 2. Set default target to multi-user (no GUI)
# =================================================================================================

echo -e "${YELLOW}[~] Setting multi-user target...${NC}"

systemctl set-default multi-user.target

echo -e "${GREEN}[+] Boot target set to multi-user${NC}"

# =================================================================================================
# 3. Configure auto-login on console
# =================================================================================================

echo -e "${YELLOW}[~] Configuring auto-login...${NC}"

# Create auto-login override for getty
mkdir -p /etc/systemd/system/getty@tty1.service.d

cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
EOF

# Also configure serial console if available
if [[ -e /dev/ttyAMA0 ]] || [[ -e /dev/ttyS0 ]]; then
    mkdir -p /etc/systemd/system/serial-getty@ttyAMA0.service.d
    cat > /etc/systemd/system/serial-getty@ttyAMA0.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 115200,38400,9600 vt102
EOF
fi

systemctl daemon-reload

echo -e "${GREEN}[+] Auto-login configured${NC}"

# =================================================================================================
# 4. Create startup script
# =================================================================================================

echo -e "${YELLOW}[~] Creating startup script...${NC}"

cat > /usr/local/bin/rasppunzel-startup.sh <<'STARTUPEOF'
#!/bin/bash

# RaspPunzel Startup Script
# Runs at boot after auto-login

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Wait for network
echo -e "${YELLOW}[~] Waiting for network...${NC}"
for i in {1..30}; do
    if ping -c 1 8.8.8.8 &>/dev/null; then
        echo -e "${GREEN}[+] Network ready${NC}"
        break
    fi
    sleep 1
done

# Display banner
clear
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    RaspPunzel Headless Server${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "  Hostname: ${GREEN}$(hostname)${NC}"
echo -e "  IP: ${GREEN}$(hostname -I | awk '{print $1}')${NC}"
echo -e "  Uptime: ${GREEN}$(uptime -p)${NC}"
echo ""

# Start services
echo -e "${YELLOW}[~] Starting RaspPunzel services...${NC}"

SERVICES=(
    "ssh"
    "hostapd"
    "dnsmasq"
    "ligolo-agent"
    "rasppunzel-web"
    "nginx"
)

for service in "${SERVICES[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        if systemctl is-active "$service" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $service: running"
        else
            systemctl start "$service" 2>/dev/null
            if systemctl is-active "$service" &>/dev/null; then
                echo -e "  ${GREEN}✓${NC} $service: started"
            else
                echo -e "  ${RED}✗${NC} $service: failed"
            fi
        fi
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    Access Points${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "  SSH:      ${YELLOW}ssh root@$(hostname -I | awk '{print $1}')${NC}"
echo -e "  Web UI:   ${YELLOW}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo -e "  WiFi AP:  ${YELLOW}SSID: PWNBOX_ADMIN${NC}"
echo ""

if systemctl is-active ligolo-agent &>/dev/null; then
    echo -e "${GREEN}[+] Ligolo Agent: Connected${NC}"
    # Show connection info if available
    if command -v lsof &>/dev/null; then
        LIGOLO_CONN=$(lsof -i -n -P 2>/dev/null | grep ligolo | grep ESTABLISHED | head -1)
        if [[ -n "$LIGOLO_CONN" ]]; then
            echo -e "    Target: $(echo $LIGOLO_CONN | awk '{print $9}' | cut -d'>' -f2)"
        fi
    fi
else
    echo -e "${YELLOW}[~] Ligolo Agent: Not running${NC}"
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo ""

# Show quick status
echo -e "${YELLOW}Quick Commands:${NC}"
echo -e "  systemctl status rasppunzel-web"
echo -e "  journalctl -u ligolo-agent -f"
echo -e "  htop"
echo ""
STARTUPEOF

chmod +x /usr/local/bin/rasppunzel-startup.sh

echo -e "${GREEN}[+] Startup script created${NC}"

# =================================================================================================
# 5. Configure .bashrc to run startup script
# =================================================================================================

echo -e "${YELLOW}[~] Configuring shell startup...${NC}"

# Add to root's .bashrc
if ! grep -q "rasppunzel-startup.sh" /root/.bashrc; then
    cat >> /root/.bashrc <<'EOF'

# RaspPunzel auto-start
if [[ -z "$RASPPUNZEL_STARTED" ]] && [[ $(tty) == "/dev/tty1" ]]; then
    export RASPPUNZEL_STARTED=1
    /usr/local/bin/rasppunzel-startup.sh
fi
EOF
fi

echo -e "${GREEN}[+] Shell configured${NC}"

# =================================================================================================
# 6. Optimize boot parameters
# =================================================================================================

echo -e "${YELLOW}[~] Optimizing boot parameters...${NC}"

# Edit /boot/cmdline.txt for faster boot
if [[ -f /boot/cmdline.txt ]]; then
    # Remove quiet and splash for verbose boot
    sed -i 's/ quiet//' /boot/cmdline.txt
    sed -i 's/ splash//' /boot/cmdline.txt
    sed -i 's/ plymouth.ignore-serial-consoles//' /boot/cmdline.txt
    
    # Add console on tty1
    if ! grep -q "console=tty1" /boot/cmdline.txt; then
        sed -i 's/$/ console=tty1/' /boot/cmdline.txt
    fi
fi

# Disable unnecessary services
DISABLE_SERVICES=(
    "bluetooth"
    "avahi-daemon"
    "triggerhappy"
    "ModemManager"
)

for service in "${DISABLE_SERVICES[@]}"; do
    systemctl disable "$service" 2>/dev/null || true
    systemctl stop "$service" 2>/dev/null || true
done

echo -e "${GREEN}[+] Boot optimized${NC}"

# =================================================================================================
# 7. Configure all RaspPunzel services to start at boot
# =================================================================================================

echo -e "${YELLOW}[~] Enabling all RaspPunzel services...${NC}"

ENABLE_SERVICES=(
    "ssh"
    "hostapd"
    "dnsmasq"
    "ligolo-agent"
    "rasppunzel-web"
    "nginx"
)

for service in "${ENABLE_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        systemctl enable "$service" 2>/dev/null || true
        echo -e "  ${GREEN}✓${NC} $service enabled"
    fi
done

echo -e "${GREEN}[+] Services enabled${NC}"

# =================================================================================================
# 8. Create recovery script
# =================================================================================================

echo -e "${YELLOW}[~] Creating recovery script...${NC}"

cat > /usr/local/bin/rasppunzel-restore-gui.sh <<'RECOVERYEOF'
#!/bin/bash

# RaspPunzel GUI Recovery Script
# Re-enables graphical interface if needed

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Restoring GUI environment..."

# Install minimal X11
apt-get update
apt-get install -y \
    xserver-xorg \
    lightdm \
    xfce4 \
    xfce4-terminal

# Re-enable graphical target
systemctl set-default graphical.target

# Remove auto-login
rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
rm -f /etc/systemd/system/serial-getty@ttyAMA0.service.d/autologin.conf

systemctl daemon-reload

echo "GUI restored. Reboot to apply changes."
echo "Run: reboot"
RECOVERYEOF

chmod +x /usr/local/bin/rasppunzel-restore-gui.sh

echo -e "${GREEN}[+] Recovery script created${NC}"
echo -e "    ${YELLOW}Emergency GUI restore: rasppunzel-restore-gui.sh${NC}"

# =================================================================================================
# Summary
# =================================================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Headless Conversion Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Changes applied:${NC}"
echo -e "  ✓ GUI packages removed (~500MB freed)"
echo -e "  ✓ Auto-login configured"
echo -e "  ✓ All services enabled at boot"
echo -e "  ✓ Boot optimized"
echo -e "  ✓ Startup script created"
echo ""
echo -e "${YELLOW}After reboot:${NC}"
echo -e "  - System will auto-login to console"
echo -e "  - All services start automatically"
echo -e "  - Access via SSH or serial console"
echo -e "  - Web UI at http://<ip>:8080"
echo ""
echo -e "${RED}Recovery:${NC}"
echo -e "  ${YELLOW}rasppunzel-restore-gui.sh${NC} - Restore GUI if needed"
echo ""
echo -e "${GREEN}Ready to reboot!${NC}"
echo ""
read -p "Reboot now? (yes/no): " -r
if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${YELLOW}[~] Rebooting...${NC}"
    sleep 2
    reboot
fi