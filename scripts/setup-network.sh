#!/bin/bash

# =============================================================================
# RaspPunzel - Configuration Réseau
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration par défaut
AP_INTERFACE="wlan1"
INTERNET_INTERFACE="wlan0"
AP_IP="192.168.10.1"
AP_NETWORK="192.168.10.0/24"
SSID="MAINTENANCE_WIFI"
PASSPHRASE="SecureP@ss123!"

# Vérification des interfaces WiFi disponibles
check_wifi_interfaces() {
    print_status "Détection des interfaces WiFi..."
    
    mapfile -t WIFI_INTERFACES < <(iw dev | grep -E "Interface|phy" | grep Interface | awk '{print $2}')
    
    if [ ${#WIFI_INTERFACES[@]} -lt 1 ]; then
        print_error "Au moins 1 interface WiFi requise"
        exit 1
    fi
    
    print_success "Interfaces détectées: ${WIFI_INTERFACES[*]}"
    
    # Attribution automatique
    if [ ${#WIFI_INTERFACES[@]} -ge 2 ]; then
        INTERNET_INTERFACE=${WIFI_INTERFACES[0]}
        AP_INTERFACE=${WIFI_INTERFACES[1]}
    else
        AP_INTERFACE=${WIFI_INTERFACES[0]}
    fi
    
    print_status "Internet: $INTERNET_INTERFACE | AP: $AP_INTERFACE"
}

# Configuration des interfaces réseau
configure_interfaces() {
    print_status "Configuration des interfaces réseau..."
    
    # Backup
    cp /etc/network/interfaces /etc/network/interfaces.backup 2>/dev/null || true
    
    cat > /etc/network/interfaces << EOF
# Loopback
auto lo
iface lo inet loopback

# Ethernet (si disponible)
allow-hotplug eth0
iface eth0 inet dhcp

# WiFi Internet (built-in généralement)
allow-hotplug $INTERNET_INTERFACE
iface $INTERNET_INTERFACE inet dhcp
wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf

# WiFi Point d'Accès (USB adapter)
allow-hotplug $AP_INTERFACE
iface $AP_INTERFACE inet static
    address $AP_IP
    netmask 255.255.255.0
    post-up /sbin/iptables-restore < /etc/iptables/rules.v4
EOF

    print_success "Interfaces configurées"
}

# Configuration du point d'accès avec hostapd
configure_hostapd() {
    print_status "Configuration hostapd..."
    
    cat > /etc/hostapd/hostapd.conf << EOF
# Interface
interface=$AP_INTERFACE
driver=nl80211

# SSID et sécurité
ssid=$SSID
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=1

# WPA2
wpa=2
wpa_passphrase=$PASSPHRASE
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP

# Options avancées
wmm_enabled=1
ht_capab=[HT40][SHORT-GI-20][SHORT-GI-40]
ieee80211n=1
country_code=FR
EOF

    # Définir le fichier de config par défaut
    sed -i 's|#DAEMON_CONF=""|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    
    print_success "Hostapd configuré"
}

# Configuration DHCP avec dnsmasq
configure_dnsmasq() {
    print_status "Configuration dnsmasq..."
    
    # Backup
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    
    cat > /etc/dnsmasq.conf << EOF
# Interface d'écoute
interface=$AP_INTERFACE
listen-address=$AP_IP
bind-interfaces

# DHCP
dhcp-range=192.168.10.10,192.168.10.50,255.255.255.0,24h
dhcp-option=option:router,$AP_IP
dhcp-option=option:dns-server,$AP_IP,8.8.8.8

# DNS
server=8.8.8.8
server=1.1.1.1

# Logs
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log

# Cache DNS
cache-size=300
EOF

    print_success "Dnsmasq configuré"
}

# Configuration du routage et NAT
configure_nat() {
    print_status "Configuration NAT et routage..."
    
    # Activation du forwarding IP
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Règles iptables
    mkdir -p /etc/iptables
    
    cat > /etc/iptables/rules.v4 << EOF
# Règles iptables pour NAT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# Masquerading pour le trafic sortant
-A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
-A POSTROUTING -o eth0 -j MASQUERADE

COMMIT

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]

# Forwarding entre interfaces
-A FORWARD -i $AP_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT
-A FORWARD -i $INTERNET_INTERFACE -o $AP_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i $AP_INTERFACE -o eth0 -j ACCEPT
-A FORWARD -i eth0 -o $AP_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Protection basique
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i $AP_INTERFACE -j ACCEPT

COMMIT
EOF

    # Installation iptables-persistent
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    
    # Application des règles
    iptables-restore < /etc/iptables/rules.v4
    
    print_success "NAT configuré"
}

# Configuration WPA supplicant pour connexion WiFi
configure_wpa_supplicant() {
    print_status "Configuration WPA supplicant..."
    
    cat > /etc/wpa_supplicant/wpa_supplicant.conf << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=FR

# Exemple de réseau - à modifier selon besoins
# network={
#     ssid="VotreWiFi"
#     psk="VotreMotDePasse"
#     priority=1
# }
EOF

    chmod 600 /etc/wpa_supplicant/wpa_supplicant.conf
    
    print_success "WPA supplicant configuré"
}

# Activation des services
enable_services() {
    print_status "Activation des services réseau..."
    
    # Désactivation NetworkManager si présent
    systemctl stop NetworkManager 2>/dev/null || true
    systemctl disable NetworkManager 2>/dev/null || true
    
    # Services réseau classiques
    systemctl enable networking
    systemctl enable hostapd
    systemctl enable dnsmasq
    
    print_success "Services activés"
}

# Test de connectivité
test_network() {
    print_status "Test de la configuration réseau..."
    
    # Test des interfaces
    if ! ip addr show $AP_INTERFACE >/dev/null 2>&1; then
        print_error "Interface $AP_INTERFACE introuvable"
        return 1
    fi
    
    # Test des services
    if ! systemctl is-enabled hostapd >/dev/null 2>&1; then
        print_error "Service hostapd non activé"
        return 1
    fi
    
    if ! systemctl is-enabled dnsmasq >/dev/null 2>&1; then
        print_error "Service dnsmasq non activé"
        return 1
    fi
    
    print_success "Configuration réseau validée"
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    echo -e "${BLUE}=== Configuration Réseau RaspPunzel ===${NC}"
    echo
    
    check_wifi_interfaces
    configure_interfaces
    configure_hostapd
    configure_dnsmasq
    configure_nat
    configure_wpa_supplicant
    enable_services
    test_network
    
    echo
    print_success "Configuration réseau terminée!"
    print_status "Redémarrage recommandé pour appliquer tous les changements"
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi