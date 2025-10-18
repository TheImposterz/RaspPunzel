#!/bin/bash
# =================================================================================================
# RaspPunzel - Network Setup Script (systemd-networkd based)
# =================================================================================================

set -euo pipefail

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

echo -e "${YELLOW}[~] Configuring network (systemd-networkd approach)...${NC}"

# =================================================================================================
# Install required packages
# =================================================================================================

echo -e "${YELLOW}[~] Installing network packages...${NC}"
apt-get update -qq
apt-get install -y -qq netfilter-persistent hostapd dnsmasq wpasupplicant systemd-resolved iproute2 > /dev/null

echo -e "${GREEN}[+] Packages installed${NC}"

# =================================================================================================
# Disable NetworkManager (causes conflicts)
# =================================================================================================

echo -e "${YELLOW}[~] Disabling NetworkManager...${NC}"
systemctl stop NetworkManager 2>/dev/null || true
systemctl disable NetworkManager 2>/dev/null || true

echo -e "${GREEN}[+] NetworkManager disabled${NC}"

# =================================================================================================
# Backup and create minimal /etc/network/interfaces
# =================================================================================================

echo -e "${YELLOW}[~] Configuring /etc/network/interfaces...${NC}"

if [[ -f /etc/network/interfaces ]]; then
    cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%s)
fi

cat > /etc/network/interfaces <<'EOF'
# RaspPunzel - Minimal interfaces file
# Network management via systemd-networkd

auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

echo -e "${GREEN}[+] /etc/network/interfaces configured${NC}"

# =================================================================================================
# Enable systemd-networkd and systemd-resolved
# =================================================================================================

echo -e "${YELLOW}[~] Enabling systemd-networkd & systemd-resolved...${NC}"

systemctl enable systemd-networkd
systemctl enable systemd-resolved

# Link resolv.conf to systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

echo -e "${GREEN}[+] systemd services enabled${NC}"

# =================================================================================================
# Configure wpa_supplicant for internet connection
# =================================================================================================

if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "${YELLOW}[~] Configuring wpa_supplicant for internet (wlan0)...${NC}"
    
    mkdir -p /etc/wpa_supplicant
    
    cat > /etc/wpa_supplicant/wpa_supplicant-wlan0.conf <<EOF
ctrl_interface=DIR=/run/wpa_supplicant GROUP=netdev
update_config=1
country=FR

network={
    ssid="${WIFI_SSID}"
    psk="${WIFI_PASSPHRASE}"
    key_mgmt=WPA-PSK
}
EOF
    
    chmod 600 /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
    
    # Enable wpa_supplicant service for wlan0
    systemctl enable wpa_supplicant@wlan0.service
    
    echo -e "${GREEN}[+] wpa_supplicant configured for wlan0${NC}"
fi

# =================================================================================================
# Configure systemd-networkd networks
# =================================================================================================

echo -e "${YELLOW}[~] Configuring systemd-networkd...${NC}"

mkdir -p /etc/systemd/network

# eth0 - Ethernet with DHCP (priority)
cat > /etc/systemd/network/10-eth0.network <<EOF
# RaspPunzel - Ethernet uplink

[Match]
Name=eth0

[Network]
DHCP=yes
IPv6AcceptRA=yes
IPMasquerade=ipv4
IPForward=ipv4
DNS=1.1.1.1
DNS=8.8.8.8

[DHCP]
RouteMetric=50
EOF

# wlan0 - WiFi with DHCP (fallback)
cat > /etc/systemd/network/20-wlan0.network <<EOF
# RaspPunzel - WiFi uplink

[Match]
Name=wlan0

[Network]
DHCP=yes
IPv6AcceptRA=yes
IPMasquerade=ipv4
IPForward=ipv4
DNS=1.1.1.1
DNS=8.8.8.8

[DHCP]
RouteMetric=100
EOF

echo -e "${GREEN}[+] systemd-networkd configured${NC}"

# =================================================================================================
# Configure Admin Access Point
# =================================================================================================

if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "${YELLOW}[~] Configuring Admin Access Point on ${WLAN_INTERFACE_ADMIN}...${NC}"
    
    # systemd-networkd config for AP interface
    cat > /etc/systemd/network/30-${WLAN_INTERFACE_ADMIN}.network <<EOF
# RaspPunzel - Admin Access Point interface

[Match]
Name=${WLAN_INTERFACE_ADMIN}

[Network]
Address=${ADMIN_AP_IP}/24
ConfigureWithoutCarrier=yes
EOF

    # dnsmasq configuration
    mkdir -p /etc/dnsmasq.d
    
    cat > /etc/dnsmasq.d/rasppunzel.conf <<EOF
# RaspPunzel DHCP/DNS Configuration

interface=${WLAN_INTERFACE_ADMIN}
bind-interfaces
listen-address=${ADMIN_AP_IP}
dhcp-range=${ADMIN_AP_DHCP_START},${ADMIN_AP_DHCP_END},${ADMIN_AP_NETMASK},${ADMIN_AP_DHCP_LEASE}
dhcp-option=3,${ADMIN_AP_IP}
dhcp-option=6,${ADMIN_AP_DNS_PRIMARY},${ADMIN_AP_DNS_SECONDARY}
EOF

    # hostapd configuration
    cat > /etc/hostapd/hostapd.conf <<EOF
# RaspPunzel Admin Access Point

interface=${WLAN_INTERFACE_ADMIN}
driver=nl80211
ssid=${ADMIN_AP_SSID}
country_code=FR
hw_mode=g
channel=${ADMIN_AP_CHANNEL}
wmm_enabled=1
ieee80211n=1
macaddr_acl=0
ignore_broadcast_ssid=${ADMIN_AP_HIDDEN}
auth_algs=1
wpa=2
wpa_passphrase=${ADMIN_AP_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

    # Configure hostapd default file
    if grep -q '^#\?DAEMON_CONF' /etc/default/hostapd 2>/dev/null; then
        sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    else
        echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
    fi
    
    # Enable IP forwarding
    echo -e "${YELLOW}[~] Enabling IP forwarding...${NC}"
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Enable services (will start at boot, NOT now to avoid timing issues)
    echo -e "${YELLOW}[~] Enabling services...${NC}"
    
    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl enable dnsmasq
    
    echo -e "${GREEN}[+] Admin AP configured on ${WLAN_INTERFACE_ADMIN}${NC}"
    echo -e "${YELLOW}[!] Services enabled but not started (will start at boot)${NC}"
fi

# =================================================================================================
# Restart systemd-networkd to apply config (safe, won't break current connection)
# =================================================================================================

echo -e "${YELLOW}[~] Applying network configuration...${NC}"

systemctl restart systemd-networkd
systemctl restart systemd-resolved

echo -e "${GREEN}[+] Network configuration applied${NC}"

# =================================================================================================
# Summary
# =================================================================================================

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}           Network Configuration Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}Network Manager:${NC}"
echo -e "  NetworkManager: ${RED}disabled${NC} (causes conflicts)"
echo -e "  systemd-networkd: ${GREEN}enabled & active${NC}"
echo -e "  systemd-resolved: ${GREEN}enabled & active${NC}"
echo ""

echo -e "${BLUE}Internet Uplink:${NC}"
echo -e "  eth0: DHCP (priority: metric 50)"
echo -e "  wlan0: DHCP (fallback: metric 100)"
if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "  WiFi SSID: ${WIFI_SSID}"
    echo -e "  Method: wpa_supplicant + DHCP"
else
    echo -e "  ${YELLOW}No WiFi credentials configured${NC}"
fi
echo -e "  NAT: ${GREEN}enabled${NC} (IPMasquerade)"
echo ""

if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "${BLUE}Admin Access Point:${NC}"
    echo -e "  Interface: ${WLAN_INTERFACE_ADMIN}"
    echo -e "  SSID: ${ADMIN_AP_SSID} $([ "${ADMIN_AP_HIDDEN}" == "1" ] && echo "(hidden)")"
    echo -e "  Password: ${ADMIN_AP_PASSPHRASE}"
    echo -e "  IP: ${ADMIN_AP_IP}"
    echo -e "  DHCP: ${ADMIN_AP_DHCP_START} - ${ADMIN_AP_DHCP_END}"
    echo ""
fi

echo -e "${BLUE}Services Status:${NC}"
echo -e "  systemd-networkd: ${GREEN}$(systemctl is-active systemd-networkd)${NC}"
echo -e "  systemd-resolved: ${GREEN}$(systemctl is-active systemd-resolved)${NC}"
if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "  wpa_supplicant@wlan0: enabled for boot"
fi
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "  hostapd: ${YELLOW}enabled (will start at boot)${NC}"
    echo -e "  dnsmasq: ${YELLOW}enabled (will start at boot)${NC}"
fi

echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}  ⚠️  REBOOT REQUIRED FOR ADMIN AP TO START  ⚠️${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Why? USB WiFi adapters need proper initialization timing.${NC}"
echo -e "${YELLOW}After reboot, all services will start in the correct order.${NC}"
echo ""
echo -e "${YELLOW}Run: sudo reboot${NC}"
echo ""