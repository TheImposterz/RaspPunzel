#!/bin/bash

# =============================================================================
# RaspPunzel - Script d'Arrêt des Services
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

LOG_FILE="/var/log/rasppunzel/stop-services.log"

# Créer le répertoire de logs
mkdir -p /var/log/rasppunzel

# Fonction de logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Arrêt du service nginx
stop_nginx() {
    print_status "Arrêt du service nginx..."
    log_message "Arrêt du service nginx"
    
    if systemctl is-active --quiet nginx; then
        systemctl stop nginx
        print_success "nginx arrêté"
        log_message "nginx arrêté avec succès"
    else
        print_warning "nginx déjà arrêté"
    fi
}

# Arrêt du service dnsmasq
stop_dnsmasq() {
    print_status "Arrêt du service dnsmasq..."
    log_message "Arrêt du service dnsmasq"
    
    if systemctl is-active --quiet dnsmasq; then
        systemctl stop dnsmasq
        print_success "dnsmasq arrêté"
        log_message "dnsmasq arrêté avec succès"
    else
        print_warning "dnsmasq déjà arrêté"
    fi
}

# Arrêt du service hostapd
stop_hostapd() {
    print_status "Arrêt du service hostapd..."
    log_message "Arrêt du service hostapd"
    
    if systemctl is-active --quiet hostapd; then
        systemctl stop hostapd
        print_success "hostapd arrêté"
        log_message "hostapd arrêté avec succès"
    else
        print_warning "hostapd déjà arrêté"
    fi
}

# Nettoyage de l'interface AP
cleanup_ap_interface() {
    print_status "Nettoyage de l'interface point d'accès..."
    log_message "Nettoyage de l'interface AP"
    
    if ip link show wlan1 &>/dev/null; then
        # Supprimer l'adresse IP
        ip addr flush dev wlan1 2>/dev/null || true
        
        # Mettre l'interface down
        ip link set wlan1 down 2>/dev/null || true
        
        print_success "Interface wlan1 nettoyée"
        log_message "Interface wlan1 nettoyée avec succès"
    else
        print_warning "Interface wlan1 non trouvée"
        log_message "ATTENTION: Interface wlan1 non trouvée"
    fi
}

# Nettoyage des règles iptables
cleanup_iptables_rules() {
    print_status "Nettoyage des règles iptables..."
    log_message "Nettoyage des règles iptables"
    
    # Nettoyer les tables NAT et FILTER
    iptables -t nat -F 2>/dev/null || true
    iptables -t filter -F 2>/dev/null || true
    
    print_success "Règles iptables nettoyées"
    log_message "Règles iptables nettoyées avec succès"
}

# Arrêt optionnel du service SSH (commenté par défaut pour garder l'accès distant)
stop_ssh() {
    # Décommenter si vous voulez arrêter SSH aussi
    # print_status "Arrêt du service SSH..."
    # log_message "Arrêt du service SSH"
    # 
    # if systemctl is-active --quiet ssh; then
    #     systemctl stop ssh
    #     print_success "SSH arrêté"
    #     log_message "SSH arrêté avec succès"
    # else
    #     print_warning "SSH déjà arrêté"
    # fi
    
    print_warning "SSH maintenu actif pour l'accès distant"
    log_message "SSH maintenu actif pour l'accès distant"
}

# Vérification de l'arrêt des services
verify_stop() {
    print_status "Vérification de l'arrêt des services..."
    log_message "Vérification de l'arrêt des services"
    
    local services=("hostapd" "dnsmasq" "nginx")
    local all_stopped=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_warning "$service: ✓ ENCORE ACTIF"
            all_stopped=false
        else
            print_success "$service: ✗ ARRÊTÉ"
        fi
    done
    
    if $all_stopped; then
        print_success "Tous les services sont arrêtés"
        log_message "Tous les services arrêtés avec succès"
        return 0
    else
        print_warning "Certains services sont encore actifs"
        log_message "ATTENTION: Certains services sont encore actifs"
        return 1
    fi
}

# Affichage des informations post-arrêt
show_stop_info() {
    echo
    print_success "=== RaspPunzel Services Arrêtés ==="
    echo
    print_status "Services arrêtés:"
    echo -e "  ${RED}✗ Point d'accès WiFi${NC}"
    echo -e "  ${RED}✗ Serveur DHCP${NC}"
    echo -e "  ${RED}✗ Interface web${NC}"
    echo -e "  ${GREEN}✓ SSH (maintenu actif)${NC}"
    echo
    print_warning "Pour redémarrer: systemctl start rasppunzel-tower"
    echo
    log_message "Informations d'arrêt affichées"
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    print_status "Arrêt des services RaspPunzel..."
    log_message "=== Arrêt des services RaspPunzel ==="
    
    # Arrêt des services dans l'ordre inverse
    stop_nginx
    stop_dnsmasq
    stop_hostapd
    cleanup_ap_interface
    cleanup_iptables_rules
    stop_ssh
    
    # Vérification finale
    sleep 2
    verify_stop
    show_stop_info
    
    log_message "Arrêt des services terminé"
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi