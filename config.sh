#!/bin/bash
# =================================================================================================
# RaspPunzel Configuration File
# =================================================================================================
# Production configuration for Raspberry Pi with 2x Ralink USB WiFi adapters
# =================================================================================================

# =================================================================================================
# Ligolo-ng Configuration
# =================================================================================================

LIGOLO_VERSION="v0.8"
LIGOLO_PROXY_HOST="YOUR_VPS_IP"         # Change to your proxy server IP
LIGOLO_PROXY_PORT="11601"
LIGOLO_IGNORE_CERT="true"
LIGOLO_RETRY_DELAY="10"
LIGOLO_AUTO_RESTART="true"
LIGOLO_BIND_ADDR="0.0.0.0"

# =================================================================================================
# Network Interfaces - Raspberry Pi with Ralink Dongles
# =================================================================================================

# Ethernet (auto-detected, leave empty for auto-detection)
MAC_ETH0=""

# Built-in WiFi (Broadcom BCM43430) - Used for internet connectivity
MAC_WLAN0=""                            # Auto-detected

# USB WiFi Dongles - Ralink RT5370 (or similar)
# Use wlan1 or wlan2 based on detection
# Run: sudo ./scripts/detect-wifi-adapters.sh to identify

# Admin Access Point - First Ralink dongle
WLAN_INTERFACE_ADMIN="wlan1"            # Usually wlan1 for first USB dongle
MAC_WLAN_ADMIN=""                       # Will be detected

# Pentest Adapter - Second Ralink dongle (optional)
WLAN_INTERFACE_PENTEST="wlan2"          # Usually wlan2 for second USB dongle
MAC_WLAN_PENTEST=""                     # Will be detected

# Legacy names (deprecated, kept for compatibility)
WLAN_INTERFACE_ALFA_NEH=""
WLAN_INTERFACE_ALFA_ACH=""

# =================================================================================================
# WiFi Credentials (for built-in WiFi to connect to internet)
# =================================================================================================

WIFI_SSID="YourHomeWiFi"                # SSID to connect to
WIFI_PASSPHRASE="YourWiFiPassword"      # WiFi password

# =================================================================================================
# Admin Access Point Configuration
# =================================================================================================

ADMIN_AP_SSID="RASPPUNZEL_ADMIN"
ADMIN_AP_PASSPHRASE="Change-Me-Now!"    # CHANGE THIS!
ADMIN_AP_HIDDEN="1"                     # 0=visible, 1=hidden (recommended)
ADMIN_AP_CHANNEL="11"
ADMIN_AP_IP="10.0.0.1"
ADMIN_AP_NETMASK="255.255.255.0"
ADMIN_AP_NETWORK="10.0.0.0/24"
ADMIN_AP_DHCP_START="10.0.0.2"
ADMIN_AP_DHCP_END="10.0.0.30"
ADMIN_AP_DHCP_LEASE="12h"
ADMIN_AP_DNS_PRIMARY="8.8.8.8"
ADMIN_AP_DNS_SECONDARY="8.8.4.4"

# =================================================================================================
# SSH Configuration
# =================================================================================================

SSH_PORT="22"
SSH_ROOT_LOGIN="yes"                    # Change to "no" for better security
SSH_PASSWORD_AUTH="yes"                 # Consider key-only auth for production


# =================================================================================================
# Pentest Tools Configuration
# =================================================================================================

ENABLE_PENTEST_TOOLS="true"         # Install WiFi pentesting tools

# =================================================================================================
# Installation Options
# =================================================================================================

ENABLE_WEB_DASHBOARD="true"             # Web-based management interface
ENABLE_CERTBOT="false"                  # SSL certificates (requires domain)
ENABLE_HEADLESS_MODE="true"             # Remove GUI, auto-login, auto-start

# =================================================================================================
# Web Dashboard Configuration
# =================================================================================================

WEB_PORT="8080"
WEB_USERNAME="admin"
WEB_PASSWORD="rasppunzel"               # CHANGE AFTER FIRST LOGIN!

# =================================================================================================
# SSL/Certbot Configuration (if ENABLE_CERTBOT=true)
# =================================================================================================

CERTBOT_EMAIL=""                        # Email for Let's Encrypt
CERTBOT_DOMAIN=""                       # Your domain name
CERTBOT_DNS_PROVIDER=""                 # cloudflare, ovh, etc.

# =================================================================================================
# System Configuration
# =================================================================================================

HOSTNAME="rasppunzel"
TIMEZONE="UTC"                          # Change to your timezone (e.g., Europe/Paris)
NTP_SERVERS="pool.ntp.org"
IP_FORWARDING="true"                    # Required for pivoting

# =================================================================================================
# Security Settings
# =================================================================================================

ENABLE_FIREWALL="false"                 # UFW firewall (optional)
ENABLE_FAIL2BAN="false"                 # Brute-force protection (optional)
SSH_ALLOWED_IPS="any"                   # Space-separated IPs or "any"

# =================================================================================================
# Logging
# =================================================================================================

LOG_LEVEL="info"                        # debug, info, warn, error
LOG_RETENTION_DAYS="7"

# =================================================================================================
# Advanced Options
# =================================================================================================

TCP_CONGESTION_CONTROL="cubic"
MAX_CONNECTIONS="1000"

# =================================================================================================
# Services to Auto-Start (for headless mode)
# =================================================================================================

HEADLESS_SERVICES=(
    "ssh"
    "ligolo-agent"
    "rasppunzel-web"
    "nginx"
    "hostapd"
    "dnsmasq"
)

# =================================================================================================
# Export Variables
# =================================================================================================

export LIGOLO_VERSION LIGOLO_PROXY_HOST LIGOLO_PROXY_PORT
export LIGOLO_IGNORE_CERT LIGOLO_RETRY_DELAY LIGOLO_AUTO_RESTART LIGOLO_BIND_ADDR
export MAC_ETH0 MAC_WLAN0
export WLAN_INTERFACE_ADMIN WLAN_INTERFACE_PENTEST
export WLAN_INTERFACE_ALFA_NEH WLAN_INTERFACE_ALFA_ACH
export MAC_WLAN_ADMIN MAC_WLAN_PENTEST
export WIFI_SSID WIFI_PASSPHRASE
export ADMIN_AP_SSID ADMIN_AP_PASSPHRASE ADMIN_AP_HIDDEN ADMIN_AP_CHANNEL
export ADMIN_AP_IP ADMIN_AP_NETMASK ADMIN_AP_NETWORK
export ADMIN_AP_DHCP_START ADMIN_AP_DHCP_END ADMIN_AP_DHCP_LEASE
export ADMIN_AP_DNS_PRIMARY ADMIN_AP_DNS_SECONDARY
export SSH_PORT SSH_ROOT_LOGIN SSH_PASSWORD_AUTH
export ENABLE_WEB_DASHBOARD ENABLE_CERTBOT ENABLE_HEADLESS_MODE ENABLE_PENTEST_TOOLS
export WEB_PORT WEB_USERNAME WEB_PASSWORD
export CERTBOT_EMAIL CERTBOT_DOMAIN CERTBOT_DNS_PROVIDER
export HOSTNAME TIMEZONE NTP_SERVERS IP_FORWARDING
export ENABLE_FIREWALL ENABLE_FAIL2BAN SSH_ALLOWED_IPS
export LOG_LEVEL LOG_RETENTION_DAYS
export TCP_CONGESTION_CONTROL MAX_CONNECTIONS