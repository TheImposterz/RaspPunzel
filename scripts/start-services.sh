#!/bin/bash

# =============================================================================
# RaspPunzel - Script de Démarrage des Services
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
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

LOG_FILE="/var/log/rasppunzel/start-services.log"

# Créer le répertoire de logs
mkdir -p /var/log/rasppunzel

# Fonction de logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Démarrage du service SSH
start_ssh() {
    print_status "Démarrage du service SSH..."
    log_message "Démarrage du service SSH"
    
    if systemctl is-active --quiet ssh; then
        print_warning "SSH déjà démarré"
    else
        systemctl start ssh
        if systemctl is-active --quiet ssh; then
            print_success "SSH démarré"
            log_message "SSH démarré avec succès"
        else
            print_error "Échec démarrage SSH"
            log_message "ERREUR: Échec démarrage SSH"
        fi
    fi
}

# Configuration de l'interface AP
configure_ap_interface() {
    print_status "Configuration de l'interface point d'accès..."
    log_message "Configuration de l'interface AP"
    
    # Vérifier si l'interface wlan1 existe
    if ! ip link show wlan1 &>/dev/null; then
        print_error "Interface wlan1 non trouvée"
        log_message "ERREUR: Interface wlan1 non trouvée"
        return 1
    fi
    
    # Configuration IP
    ip addr flush dev wlan1 2>/dev/null || true
    ip addr add 192.168.10.1/24 dev wlan1
    ip link set wlan1 up
    
    # Vérification
    if ip addr show wlan1 | grep -q "192.168.10.1"; then
        print_success "Interface wlan1 configurée: 192.168.10.1"
        log_message "Interface wlan1 configurée avec succès"
    else
        print_error "Échec configuration interface wlan1"
        log_message "ERREUR: Échec configuration interface wlan1"
        return 1
    fi
}

# Démarrage du service hostapd
start_hostapd() {
    print_status "Démarrage du service hostapd..."
    log_message "Démarrage du service hostapd"
    
    if systemctl is-active --quiet hostapd; then
        print_warning "hostapd déjà démarré"
    else
        # Vérification de la configuration
        if [ ! -f /etc/hostapd/hostapd.conf ]; then
            print_error "Configuration hostapd manquante"
            log_message "ERREUR: Configuration hostapd manquante"
            return 1
        fi
        
        systemctl start hostapd
        sleep 3
        
        if systemctl is-active --quiet hostapd; then
            print_success "hostapd démarré"
            log_message "hostapd démarré avec succès"
        else
            print_error "Échec démarrage hostapd"
            log_message "ERREUR: Échec démarrage hostapd"
            # Afficher les logs pour débugger
            journalctl -u hostapd --no-pager -n 5
        fi
    fi
}

# Démarrage du service dnsmasq
start_dnsmasq() {
    print_status "Démarrage du service dnsmasq..."
    log_message "Démarrage du service dnsmasq"
    
    if systemctl is-active --quiet dnsmasq; then
        print_warning "dnsmasq déjà démarré"
    else
        # Vérification de la configuration
        if [ ! -f /etc/dnsmasq.conf ]; then
            print_error "Configuration dnsmasq manquante"
            log_message "ERREUR: Configuration dnsmasq manquante"
            return 1
        fi
        
        systemctl start dnsmasq
        sleep 2
        
        if systemctl is-active --quiet dnsmasq; then
            print_success "dnsmasq démarré"
            log_message "dnsmasq démarré avec succès"
        else
            print_error "Échec démarrage dnsmasq"
            log_message "ERREUR: Échec démarrage dnsmasq"
            # Afficher les logs pour débugger
            journalctl -u dnsmasq --no-pager -n 5
        fi
    fi
}

# Démarrage du service nginx
start_nginx() {
    print_status "Démarrage du service nginx..."
    log_message "Démarrage du service nginx"
    
    if systemctl is-active --quiet nginx; then
        print_warning "nginx déjà démarré"
    else
        # Vérification de la configuration
        if ! nginx -t &>/dev/null; then
            print_error "Configuration nginx invalide"
            log_message "ERREUR: Configuration nginx invalide"
            return 1
        fi
        
        systemctl start nginx
        sleep 2
        
        if systemctl is-active --quiet nginx; then
            print_success "nginx démarré"
            log_message "nginx démarré avec succès"
        else
            print_error "Échec démarrage nginx"
            log_message "ERREUR: Échec démarrage nginx"
        fi
    fi
}

# Application des règles iptables
apply_iptables_rules() {
    print_status "Application des règles iptables..."
    log_message "Application des règles iptables"
    
    if [ -f /etc/iptables/rules.v4 ]; then
        iptables-restore < /etc/iptables/rules.v4
        print_success "Règles iptables appliquées"
        log_message "Règles iptables appliquées avec succès"
    else
        print_warning "Fichier de règles iptables non trouvé"
        log_message "ATTENTION: Fichier de règles iptables non trouvé"
    fi
}

# Vérification finale des services
verify_services() {
    print_status "Vérification des services..."
    log_message "Vérification des services"
    
    local all_ok=true
    local services=("ssh" "hostapd" "dnsmasq" "nginx")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_success "$service: ✓ ACTIF"
        else
            print_error "$service: ✗ INACTIF"
            all_ok=false
        fi
    done
    
    # Vérification des ports
    echo
    print_status "Vérification des ports..."
    
    if ss -tlnp | grep -q ":22"; then
        print_success "Port 22 (SSH): ✓ OUVERT"
    else
        print_warning "Port 22 (SSH): ✗ FERMÉ"
    fi
    
    if ss -tlnp | grep -q ":8080"; then
        print_success "Port 8080 (Web): ✓ OUVERT"
    else
        print_warning "Port 8080 (Web): ✗ FERMÉ"
    fi
    
    if ss -ulnp | grep -q ":67"; then
        print_success "Port 67 (DHCP): ✓ OUVERT"
    else
        print_warning "Port 67 (DHCP): ✗ FERMÉ"
    fi
    
    if $all_ok; then
        log_message "Tous les services démarrés avec succès"
        return 0
    else
        log_message "ERREUR: Certains services ont échoué"
        return 1
    fi
}

# Affichage des informations de connexion
show_connection_info() {
    echo
    print_success "=== RaspPunzel Services Démarrés ==="
    echo
    print_status "Informations de connexion:"
    echo -e "  ${GREEN}WiFi AP (caché)${NC}: MAINTENANCE_WIFI"
    echo -e "  ${GREEN}Mot de passe${NC}   : SecureP@ss123!"
    echo -e "  ${GREEN}IP du Pi${NC}       : 192.168.10.1"
    echo -e "  ${GREEN}Interface Web${NC}  : http://192.168.10.1:8080"
    echo -e "  ${GREEN}SSH${NC}            : ssh admin@192.168.10.1"
    echo
    log_message "Informations de connexion affichées"
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    print_status "Démarrage des services RaspPunzel..."
    log_message "=== Démarrage des services RaspPunzel ==="
    
    # Attendre que le réseau soit prêt
    sleep 5
    
    # Démarrage des services dans l'ordre
    start_ssh
    configure_ap_interface
    start_hostapd
    start_dnsmasq
    start_nginx
    apply_iptables_rules
    
    # Vérification finale
    sleep 3
    if verify_services; then
        show_connection_info
        log_message "Démarrage des services terminé avec succès"
        exit 0
    else
        print_error "Certains services ont échoué au démarrage"
        log_message "ERREUR: Échec du démarrage de certains services"
        exit 1
    fi
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi