#!/bin/bash

# =================================================================================================
# RaspPunzel - Network Setup Script
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

echo -e "${YELLOW}[~] Configuring network...${NC}"

# Install required packages
echo -e "${YELLOW}[~] Installing network packages...${NC}"
apt-get update -qq
apt-get install -y -qq dnsmasq hostapd iptables-persistent > /dev/null

# Stop services for configuration
systemctl stop dnsmasq hostapd 2>/dev/null || true
systemctl stop NetworkManager 2>/dev/null || true
systemctl disable NetworkManager 2>/dev/null || true

# Configure persistent interface names
echo -e "${YELLOW}[~] Configuring persistent interface names...${NC}"
cat > /etc/udev/rules.d/70-persistent-net.rules <<EOF
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="${MAC_ETH0}", NAME="eth0"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="${MAC_WLAN0}", NAME="wlan0"
EOF

cat > /etc/udev/rules.d/73-usb-net-by-mac.rules <<EOF
IMPORT{cmdline}="net.ifnames", ENV{net.ifnames}=="0", GOTO="usb_net_by_mac_end"
PROGRAM="/bin/readlink /etc/udev/rules.d/80-net-setup-link.rules", RESULT=="/dev/null", GOTO="usb_net_by_mac_end"
ACTION=="add", SUBSYSTEM=="net", SUBSYSTEMS=="usb", NAME=="", \
    ATTR{address}=="?[014589cd]:*", \
    IMPORT{builtin}="net_id", NAME="\$env{ID_NET_NAME_MAC}"
LABEL="usb_net_by_mac_end"
EOF

systemctl restart systemd-udevd

# Configure network interfaces
echo -e "${YELLOW}[~] Configuring network interfaces...${NC}"
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

# Ethernet - DHCP
auto eth0
allow-hotplug eth0
iface eth0 inet dhcp

# Built-in WiFi - Connect to Internet
auto wlan0
allow-hotplug wlan0
iface wlan0 inet dhcp
wpa-conf /etc/wpa_supplicant.conf
iface default inet dhcp

# Admin AP Interface
allow-hotplug ${WLAN_INTERFACE_ADMIN}
iface ${WLAN_INTERFACE_ADMIN} inet static
  address ${ADMIN_AP_IP}
  netmask ${ADMIN_AP_NETMASK}
EOF

# Configure wpa_supplicant for internet connection
echo -e "${YELLOW}[~] Configuring WiFi credentials...${NC}"
wpa_passphrase "${WIFI_SSID}" "${WIFI_PASSPHRASE}" > /etc/wpa_supplicant.conf

# Configure dnsmasq
echo -e "${YELLOW}[~] Configuring DHCP/DNS...${NC}"
cat > /etc/dnsmasq.conf <<EOF
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
echo -e "${YELLOW}[~] Configuring Admin Access Point...${NC}"
cat > /etc/hostapd/hostapd.conf <<EOF
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

# Enable services
echo -e "${YELLOW}[~] Enabling services...${NC}"
systemctl unmask hostapd
systemctl enable hostapd
systemctl enable dnsmasq

echo -e "${GREEN}[+] Network configuration complete${NC}"
echo ""
echo "  Admin AP SSID: ${ADMIN_AP_SSID}"
echo "  Admin AP IP: ${ADMIN_AP_IP}"
echo "  DHCP Range: ${ADMIN_AP_DHCP_START} - ${ADMIN_AP_DHCP_END}"
echo ""