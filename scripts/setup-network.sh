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
# Configure systemd-networkd for wlan0 (internet uplink)
# =================================================================================================

echo -e "${YELLOW}[~] Configuring systemd-networkd for wlan0 (uplink)...${NC}"

mkdir -p /etc/systemd/network

cat > /etc/systemd/network/10-wlan0.network <<EOF
# RaspPunzel - Internet uplink via wlan0

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

echo -e "${GREEN}[+] wlan0 configured (DHCP + NAT)${NC}"

# =================================================================================================
# Configure Admin Access Point
# =================================================================================================

if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "${YELLOW}[~] Configuring Admin Access Point on ${WLAN_INTERFACE_ADMIN}...${NC}"
    
    # systemd-networkd config for AP interface
    cat > /etc/systemd/network/20-${WLAN_INTERFACE_ADMIN}.network <<EOF
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
    
    echo -e "${GREEN}[+] Admin AP configured on ${WLAN_INTERFACE_ADMIN}${NC}"
fi

# =================================================================================================
# Start services
# =================================================================================================

echo -e "${YELLOW}[~] Starting services...${NC}"

# Restart systemd-networkd to apply config
systemctl restart systemd-networkd
systemctl restart systemd-resolved

# Wait a bit for interfaces to settle
sleep 2

# Force interfaces UP
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    ip link set ${WLAN_INTERFACE_ADMIN} up 2>/dev/null || true
fi
ip link set wlan0 up 2>/dev/null || true

# Start wpa_supplicant for internet
if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    systemctl start wpa_supplicant@wlan0.service
fi

# Start dnsmasq and hostapd
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    systemctl enable dnsmasq
    systemctl restart dnsmasq
    
    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl restart hostapd
fi

sleep 2

echo -e "${GREEN}[+] Services started${NC}"

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
echo -e "  systemd-networkd: ${GREEN}enabled${NC}"
echo -e "  systemd-resolved: ${GREEN}enabled${NC}"
echo ""

echo -e "${BLUE}Internet Uplink:${NC}"
echo -e "  Interface: wlan0 (built-in WiFi)"
if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "  SSID: ${WIFI_SSID}"
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

echo -e "${BLUE}Services:${NC}"
echo -e "  systemd-networkd: $(systemctl is-active systemd-networkd)"
echo -e "  systemd-resolved: $(systemctl is-active systemd-resolved)"
if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "  wpa_supplicant@wlan0: $(systemctl is-active wpa_supplicant@wlan0 2>/dev/null || echo 'inactive')"
fi
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "  hostapd: $(systemctl is-active hostapd)"
    echo -e "  dnsmasq: $(systemctl is-active dnsmasq)"
fi

echo ""
echo -e "${YELLOW}Note: A reboot is recommended to ensure all changes take effect${NC}"
echo -e "${YELLOW}      sudo reboot${NC}"
echo ""


# =================================================================================================
# Configure persistent interface names
# =================================================================================================

echo -e "${YELLOW}[~] Configuring persistent interface names...${NC}"

# Backup old rules
if [[ -f /etc/udev/rules.d/70-persistent-net.rules ]]; then
    mv /etc/udev/rules.d/70-persistent-net.rules /etc/udev/rules.d/70-persistent-net.rules.old
fi

if [[ -f /etc/udev/rules.d/73-usb-net-by-mac.rules ]]; then
    mv /etc/udev/rules.d/73-usb-net-by-mac.rules /etc/udev/rules.d/73-usb-net-by-mac.rules.old
fi

# Create persistent naming rules
cat > /etc/udev/rules.d/70-persistent-net.rules <<EOF
# RaspPunzel - Persistent network interface names
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="${MAC_ETH0}", NAME="eth0"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="${MAC_WLAN0}", NAME="wlan0"
EOF

# USB WiFi adapters - MAC-based naming
cat > /etc/udev/rules.d/73-usb-net-by-mac.rules <<EOF
# RaspPunzel - USB WiFi adapters persistent naming
IMPORT{cmdline}="net.ifnames", ENV{net.ifnames}=="0", GOTO="usb_net_by_mac_end"
PROGRAM="/bin/readlink /etc/udev/rules.d/80-net-setup-link.rules", RESULT=="/dev/null", GOTO="usb_net_by_mac_end"

ACTION=="add", SUBSYSTEM=="net", SUBSYSTEMS=="usb", NAME=="", \
    ATTR{address}=="?[014589cd]:*", \
    IMPORT{builtin}="net_id", NAME="\$env{ID_NET_NAME_MAC}"

LABEL="usb_net_by_mac_end"
EOF

systemctl restart systemd-udevd

echo -e "${GREEN}[+] Persistent interface names configured${NC}"

# =================================================================================================
# Configure network interfaces
# =================================================================================================

echo -e "${YELLOW}[~] Configuring network interfaces...${NC}"

# Backup old config
if [[ -f /etc/network/interfaces ]]; then
    mv /etc/network/interfaces /etc/network/interfaces.old
fi

cat > /etc/network/interfaces <<EOF
# RaspPunzel Network Configuration

auto lo
iface lo inet loopback

# Ethernet - DHCP (managed by NetworkManager or this config)
auto eth0
allow-hotplug eth0
iface eth0 inet dhcp

# Built-in WiFi (Broadcom) - For internet connectivity
# Managed by NetworkManager or wpa_supplicant
auto wlan0
allow-hotplug wlan0
iface wlan0 inet dhcp
wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf
iface default inet dhcp

EOF

# Add AP interface if configured
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    cat >> /etc/network/interfaces <<EOF
# Admin Access Point - ${WLAN_INTERFACE_ADMIN} (Ralink dongle)
allow-hotplug ${WLAN_INTERFACE_ADMIN}
iface ${WLAN_INTERFACE_ADMIN} inet static
    address ${ADMIN_AP_IP}
    netmask ${ADMIN_AP_NETMASK}
    up route add -net ${ADMIN_AP_NETWORK} gw ${ADMIN_AP_IP}

EOF
fi

# Add pentest interface if configured
if [[ -n "${WLAN_INTERFACE_PENTEST}" && "${WLAN_INTERFACE_PENTEST}" != "none" ]]; then
    cat >> /etc/network/interfaces <<EOF
# Pentest WiFi Adapter - ${WLAN_INTERFACE_PENTEST} (Available, disabled by default)
iface ${WLAN_INTERFACE_PENTEST} inet manual

EOF
fi

# Add legacy interfaces if configured
if [[ -n "${WLAN_INTERFACE_ALFA_NEH}" && "${WLAN_INTERFACE_ALFA_NEH}" != "none" ]]; then
    cat >> /etc/network/interfaces <<EOF
# Alfa AWUS036NEH - Disabled by default
iface ${WLAN_INTERFACE_ALFA_NEH} inet manual

EOF
fi

if [[ -n "${WLAN_INTERFACE_ALFA_ACH}" && "${WLAN_INTERFACE_ALFA_ACH}" != "none" ]]; then
    cat >> /etc/network/interfaces <<EOF
# Alfa AWUS036ACH - Disabled by default
iface ${WLAN_INTERFACE_ALFA_ACH} inet manual

EOF
fi

echo -e "${GREEN}[+] Network interfaces configured${NC}"

# =================================================================================================
# Configure WiFi credentials for internet
# =================================================================================================

if [[ -n "${WIFI_SSID}" && "${WIFI_SSID}" != "NotUsed" ]]; then
    echo -e "${YELLOW}[~] Configuring WiFi credentials...${NC}"
    
    mkdir -p /etc/wpa_supplicant
    wpa_passphrase "${WIFI_SSID}" "${WIFI_PASSPHRASE}" > /etc/wpa_supplicant/wpa_supplicant.conf
    
    echo -e "${GREEN}[+] WiFi credentials configured${NC}"
fi

# =================================================================================================
# Configure Admin Access Point
# =================================================================================================

if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "${YELLOW}[~] Configuring Admin Access Point...${NC}"
    
    # Configure dnsmasq
    if [[ -f /etc/dnsmasq.conf ]]; then
        mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old
    fi
    
    cat > /etc/dnsmasq.conf <<EOF
# RaspPunzel DHCP/DNS Configuration

interface=${WLAN_INTERFACE_ADMIN}
dhcp-authoritative
dhcp-range=${ADMIN_AP_DHCP_START},${ADMIN_AP_DHCP_END},${ADMIN_AP_NETMASK},${ADMIN_AP_DHCP_LEASE}
dhcp-option=3,${ADMIN_AP_IP}
dhcp-option=6,${ADMIN_AP_DNS_PRIMARY}
server=${ADMIN_AP_DNS_PRIMARY}
server=${ADMIN_AP_DNS_SECONDARY}
log-queries
log-dhcp
listen-address=${ADMIN_AP_IP}
bind-interfaces


EOF

    # Configure hostapd
    if [[ -f /etc/hostapd/hostapd.conf ]]; then
        mv /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.old
    fi
    
    cat > /etc/hostapd/hostapd.conf <<EOF
# RaspPunzel Admin Access Point

interface=${WLAN_INTERFACE_ADMIN}
driver=nl80211
ssid=${ADMIN_AP_SSID}
hw_mode=g
channel=${ADMIN_AP_CHANNEL}
macaddr_acl=0
ignore_broadcast_ssid=${ADMIN_AP_HIDDEN}
auth_algs=1
wpa=2
wpa_passphrase=${ADMIN_AP_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
wpa_group_rekey=86400
ieee80211n=1
wme_enabled=1
EOF

    # Enable IP forwarding
    echo -e "${YELLOW}[~] Enabling IP forwarding...${NC}"
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Configure NAT
    echo -e "${YELLOW}[~] Configuring NAT...${NC}"
    
    # Find internet interface
    PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "${PRIMARY_IFACE}" ]]; then
        # Clear existing rules
        iptables -t nat -F
        iptables -F FORWARD
        
        # Setup NAT
        iptables -t nat -A POSTROUTING -o "${PRIMARY_IFACE}" -j MASQUERADE
        iptables -A FORWARD -i "${WLAN_INTERFACE_ADMIN}" -o "${PRIMARY_IFACE}" -j ACCEPT
        iptables -A FORWARD -i "${PRIMARY_IFACE}" -o "${WLAN_INTERFACE_ADMIN}" -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # Save rules
        netfilter-persistent save
        
        echo -e "${GREEN}[+] NAT configured (${WLAN_INTERFACE_ADMIN} → ${PRIMARY_IFACE})${NC}"
    else
        echo -e "${YELLOW}[~] No internet interface found, NAT not configured${NC}"
    fi
    
    # Enable and start services
    echo -e "${YELLOW}[~] Enabling services...${NC}"
    
    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl enable dnsmasq
    
    # Don't start now, will start at boot or manually
    echo -e "${GREEN}[+] Services enabled (will start at next boot)${NC}"
else
    echo -e "${YELLOW}[~] No Admin AP configured, skipping${NC}"
fi

# =================================================================================================
# Summary
# =================================================================================================

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}           Network Configuration Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
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

echo -e "${BLUE}Services:${NC}"
echo -e "  NetworkManager: $(systemctl is-active NetworkManager 2>/dev/null || echo 'not installed')"
if [[ -n "${WLAN_INTERFACE_ADMIN}" && "${WLAN_INTERFACE_ADMIN}" != "none" ]]; then
    echo -e "  hostapd: enabled (not started yet)"
    echo -e "  dnsmasq: enabled (not started yet)"
fi

echo ""
echo -e "${YELLOW}Note: Services will start automatically at next boot${NC}"
echo ""