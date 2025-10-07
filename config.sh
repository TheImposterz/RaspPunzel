#!/bin/bash

# =================================================================================================
# RaspPunzel Configuration File
# =================================================================================================
# Edit this file before running install.sh
# =================================================================================================

# -------------------------------------------------------------------------------------------------
# LIGOLO-NG CONFIGURATION
# -------------------------------------------------------------------------------------------------

# Ligolo-ng version (check: https://github.com/nicocha30/ligolo-ng/releases)
LIGOLO_VERSION="v0.8"

# Ligolo PROXY server (YOUR attacker machine)
# The Raspberry Pi agent will connect to this address
LIGOLO_PROXY_HOST="192.168.1.100"     # Your attacker machine IP/hostname / can use a NAT address or ngrok tcp redirect
LIGOLO_PROXY_PORT="11601"              # Proxy listening port

# Connection options
LIGOLO_IGNORE_CERT="true"              # Accept self-signed certificates
LIGOLO_RETRY_DELAY="10"                # Reconnection delay in seconds
LIGOLO_AUTO_RESTART="true"             # Auto-restart agent on failure

# -------------------------------------------------------------------------------------------------
# NETWORK INTERFACES
# -------------------------------------------------------------------------------------------------
# IMPORTANT: Find your MAC addresses with: ip link show

# Built-in Ethernet MAC address
MAC_ETH0="b8:27:eb:12:34:56"

# Built-in WiFi MAC address
MAC_WLAN0="b8:27:eb:ab:cd:ef"

# USB WiFi adapter for Admin AP (MAC without colons)
# Example: If MAC is 00:c0:ca:a1:b2:c3 → wlx00c0caa1b2c3
WLAN_INTERFACE_ADMIN="wlx00c0caa1b2c3"

# Additional USB WiFi adapters (optional - for attacks/monitoring)
WLAN_INTERFACE_ALFA_NEH="wlxaabbccddeeff"
WLAN_INTERFACE_ALFA_ACH="wlxaabbccddeeff"

# -------------------------------------------------------------------------------------------------
# INTERNET CONNECTION
# -------------------------------------------------------------------------------------------------

# WiFi credentials for Raspberry Pi to connect to internet
WIFI_SSID="YourHomeWiFi"
WIFI_PASSPHRASE="YourWiFiPassword"

# -------------------------------------------------------------------------------------------------
# ADMIN ACCESS POINT
# -------------------------------------------------------------------------------------------------

# Admin AP SSID
ADMIN_AP_SSID="PIVOT_ADMIN"

# Admin AP Password (min 8 characters)
ADMIN_AP_PASSPHRASE="SecurePass123!"

# Hide SSID (0=visible, 1=hidden)
ADMIN_AP_HIDDEN="0"

# WiFi channel (1-11)
ADMIN_AP_CHANNEL="6"

# Admin AP IP configuration
ADMIN_AP_IP="10.0.0.1"
ADMIN_AP_NETMASK="255.255.255.0"
ADMIN_AP_NETWORK="10.0.0.0/24"

# DHCP range for Admin AP
ADMIN_AP_DHCP_START="10.0.0.2"
ADMIN_AP_DHCP_END="10.0.0.30"
ADMIN_AP_DHCP_LEASE="12h"

# DNS servers for Admin AP clients
ADMIN_AP_DNS_PRIMARY="8.8.8.8"
ADMIN_AP_DNS_SECONDARY="8.8.4.4"

# -------------------------------------------------------------------------------------------------
# SSH CONFIGURATION
# -------------------------------------------------------------------------------------------------

# SSH port
SSH_PORT="22"

# Allow root login (yes/no)
SSH_ROOT_LOGIN="yes"

# Allow password authentication (yes/no)
SSH_PASSWORD_AUTH="yes"

# -------------------------------------------------------------------------------------------------
# WEB DASHBOARD
# -------------------------------------------------------------------------------------------------

# Enable web dashboard
ENABLE_WEB_DASHBOARD="true"

# Web dashboard port
WEB_PORT="5000"

# Web dashboard credentials
WEB_USERNAME="admin"
WEB_PASSWORD="rasppunzel"

# -------------------------------------------------------------------------------------------------
# SYSTEM CONFIGURATION
# -------------------------------------------------------------------------------------------------

# Hostname
HOSTNAME="rasppunzel"

# Timezone (use: timedatectl list-timezones)
TIMEZONE="UTC"

# NTP servers
NTP_SERVERS="pool.ntp.org"

# Enable IP forwarding
IP_FORWARDING="true"

# -------------------------------------------------------------------------------------------------
# SECURITY SETTINGS
# -------------------------------------------------------------------------------------------------

# Enable firewall (iptables)
ENABLE_FIREWALL="true"

# Enable fail2ban for SSH
ENABLE_FAIL2BAN="false"

# Allowed SSH IPs (comma-separated or "any")
# Example: "192.168.1.0/24,10.0.0.0/24"
SSH_ALLOWED_IPS="any"

# -------------------------------------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------------------------------------

# Log level (debug/info/warning/error)
LOG_LEVEL="info"

# Log retention (days)
LOG_RETENTION_DAYS="7"

# -------------------------------------------------------------------------------------------------
# ADVANCED OPTIONS
# -------------------------------------------------------------------------------------------------

# Ligolo bind address (0.0.0.0 = all interfaces)
LIGOLO_BIND_ADDR="0.0.0.0"

# TCP congestion control (cubic/bbr/reno)
TCP_CONGESTION_CONTROL="cubic"

# Maximum connections
MAX_CONNECTIONS="1000"

# -------------------------------------------------------------------------------------------------
# EXPORT ALL VARIABLES
# -------------------------------------------------------------------------------------------------

export LIGOLO_VERSION LIGOLO_PORT TUN_INTERFACE TUN_IP
export MAC_ETH0 MAC_WLAN0
export WLAN_INTERFACE_ADMIN WLAN_INTERFACE_ALFA_NEH WLAN_INTERFACE_ALFA_ACH
export WIFI_SSID WIFI_PASSPHRASE
export ADMIN_AP_SSID ADMIN_AP_PASSPHRASE ADMIN_AP_HIDDEN ADMIN_AP_CHANNEL
export ADMIN_AP_IP ADMIN_AP_NETMASK ADMIN_AP_NETWORK
export ADMIN_AP_DHCP_START ADMIN_AP_DHCP_END ADMIN_AP_DHCP_LEASE
export ADMIN_AP_DNS_PRIMARY ADMIN_AP_DNS_SECONDARY
export SSH_PORT SSH_ROOT_LOGIN SSH_PASSWORD_AUTH
export ENABLE_WEB_DASHBOARD WEB_PORT WEB_USERNAME WEB_PASSWORD
export HOSTNAME TIMEZONE NTP_SERVERS IP_FORWARDING
export ENABLE_FIREWALL ENABLE_FAIL2BAN SSH_ALLOWED_IPS
export LOG_LEVEL LOG_RETENTION_DAYS
export LIGOLO_BIND_ADDR TCP_CONGESTION_CONTROL MAX_CONNECTIONS
