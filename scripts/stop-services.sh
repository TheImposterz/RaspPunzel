#!/bin/bash

# =============================================================================
# RaspPunzel - Script d'Arrêt des Services
# Version intégrée avec Dashboard Web
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

# Arrêt du dashboard web (si installé)
stop_web_dashboard() {
    if ! systemctl list-unit-files | grep -q "rasppunzel-web.service"; then
        print_status "Dashboard web non installé, passage ignoré"
        return 0
    fi
    
    print_status "Arrêt du dashboard web RaspPunzel..."
    log_message "Arrêt du dashboard web"
    
    if systemctl is-active --quiet rasppunzel-web; then
        systemctl stop rasppunzel-web
        
        # Attendre un peu puis vérifier
        sleep 2
        if ! systemctl is-active --quiet rasppunzel-web; then
            print_success "Dashboard web arrêté"
            log_message "Dashboard web arrêté avec succès"
        else
            print_warning "Dashboard web encore actif, forçage..."
            systemctl kill rasppunzel-web
            sleep 1
        fi
    else
        print_warning "Dashboard web déjà arrêté"
    fi
    
    # Nettoyage des processus Python restants
    pkill -f "rasppunzel.*app.py" 2>/dev/null || true
    pkill -f "python.*rasppunzel" 2>/dev/null || true
}

# Arrêt du service nginx (seulement si dashboard web pas installé)
stop_nginx() {
    if systemctl list-unit-files | grep -q "rasppunzel-web.service"; then
        print_status "Dashboard web installé, nginx ignoré"
        return 0
    fi
    
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

# Arrêt des services RaspPunzel spécifiques
stop_rasppunzel_services() {
    print_status "Arrêt des services RaspPunzel..."
    log_message "Arrêt des services RaspPunzel"
    
    local rasppunzel_services=("rasppunzel-tower" "rasppunzel-network")
    
    for service in "${rasppunzel_services[@]}"; do
        if systemctl list-unit-files | grep -q "$service.service"; then
            if systemctl is-active --quiet "$service"; then
                print_status "Arrêt de $service..."
                systemctl stop "$service"
                sleep 1
                
                if ! systemctl is-active --quiet "$service"; then
                    print_success "$service arrêté"
                    log_message "$service arrêté avec succès"
                else
                    print_warning "$service encore actif"
                    log_message "ATTENTION: $service encore actif"
                fi
            else
                print_warning "$service déjà arrêté"
            fi
        else
            print_status "$service non installé"
        fi
    done
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
    
    # Nettoyer les tables NAT et FILTER (avec gestion d'erreur)
    iptables -t nat -F 2>/dev/null || true
    iptables -t filter -F FORWARD 2>/dev/null || true
    
    print_success "Règles iptables nettoyées"
    log_message "Règles iptables nettoyées avec succès"
}

# Arrêt des outils de sécurité en cours
stop_security_tools() {
    print_status "Arrêt des outils de sécurité en cours..."
    log_message "Arrêt des outils de sécurité"
    
    # Liste des processus à arrêter
    local tools_processes=(
        "nmap" "masscan" "kismet" "airodump-ng" "wifite" "aircrack-ng"
        "reaver" "bully" "nikto" "gobuster" "sqlmap" "hydra" "john"
        "hashcat" "medusa" "msfconsole" "wireshark" "ettercap"
        "bettercap" "tcpdump" "wifipumpkin3" "wifiphisher"
    )
    
    local stopped_count=0
    for tool in "${tools_processes[@]}"; do
        if pgrep "$tool" > /dev/null 2>&1; then
            print_status "Arrêt de $tool..."
            pkill "$tool" 2>/dev/null || true
            sleep 0.5
            
            # Force kill si nécessaire
            if pgrep "$tool" > /dev/null 2>&1; then
                pkill -9 "$tool" 2>/dev/null || true
            fi
            
            ((stopped_count++))
        fi
    done
    
    if [ $stopped_count -gt 0 ]; then
        print_success "$stopped_count outil(s) de sécurité arrêté(s)"
        log_message "$stopped_count outil(s) de sécurité arrêté(s)"
    else
        print_status "Aucun outil de sécurité en cours d'exécution"
    fi
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
    
    local services=("hostapd" "dnsmasq")
    local all_stopped=true
    
    # Ajouter nginx ou rasppunzel-web selon l'installation
    if systemctl list-unit-files | grep -q "rasppunzel-web.service"; then
        services+=("rasppunzel-web")
    else
        services+=("nginx")
    fi
    
    # Ajouter les services RaspPunzel s'ils existent
    for rp_service in "rasppunzel-tower" "rasppunzel-network"; do
        if systemctl list-unit-files | grep -q "$rp_service.service"; then
            services+=("$rp_service")
        fi
    done
    
    echo
    print_status "État des services :"
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_warning "$service: ✓ ENCORE ACTIF"
            all_stopped=false
        else
            print_success "$service: ✗ ARRÊTÉ"
        fi
    done
    
    # Vérification des ports
    echo
    print_status "Vérification des ports..."
    
    if ss -tlnp 2>/dev/null | grep -q ":8080"; then
        print_warning "Port 8080: ✓ ENCORE OUVERT"
        all_stopped=false
    else
        print_success "Port 8080: ✗ FERMÉ"
    fi
    
    if ss -ulnp 2>/dev/null | grep -q ":67"; then
        print_warning "Port 67 (DHCP): ✓ ENCORE OUVERT"
        all_stopped=false
    else
        print_success "Port 67 (DHCP): ✗ FERMÉ"
    fi
    
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
    
    if systemctl list-unit-files | grep -q "rasppunzel-web.service"; then
        echo -e "  ${RED}✗ Dashboard Web${NC}"
    else
        echo -e "  ${RED}✗ Interface web (nginx)${NC}"
    fi
    
    # Services RaspPunzel
    for service in "rasppunzel-network" "rasppunzel-tower"; do
        if systemctl list-unit-files | grep -q "$service.service"; then
            echo -e "  ${RED}✗ $service${NC}"
        fi
    done
    
    echo -e "  ${GREEN}✓ SSH (maintenu actif)${NC}"
    echo
    print_warning "Pour redémarrer: bash scripts/start-services.sh"
    print_status "Ou utilisez: make start"
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
    
    # Arrêt des services dans l'ordre inverse du démarrage
    
    # 1. Dashboard web et outils de sécurité en premier
    stop_security_tools
    stop_web_dashboard
    
    # 2. Services web
    stop_nginx
    
    # 3. Services RaspPunzel spécifiques
    stop_rasppunzel_services
    
    # 4. Services réseau
    stop_dnsmasq
    stop_hostapd
    
    # 5. Nettoyage réseau
    cleanup_ap_interface
    cleanup_iptables_rules
    
    # 6. SSH (optionnel)
    stop_ssh
    
    # Vérification finale
    sleep 2
    verify_stop
    show_stop_info
    
    log_message "Arrêt des services terminé"
}

# Gestion des arguments
case "${1:-}" in
    --force)
        print_warning "Mode forcé activé - arrêt de SSH inclus"
        stop_ssh_forced=true
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --force    Arrêt forcé (inclut SSH)"
        echo "  --help     Afficher cette aide"
        echo ""
        echo "Par défaut, SSH reste actif pour maintenir l'accès distant"
        exit 0
        ;;
    "")
        # Mode normal
        ;;
    *)
        print_error "Option inconnue: $1"
        echo "Utilisez --help pour voir les options disponibles"
        exit 1
        ;;
esac

# Fonction SSH forcée si demandée
if [ "${stop_ssh_forced:-false}" = true ]; then
    stop_ssh() {
        print_status "Arrêt forcé du service SSH..."
        log_message "Arrêt forcé du service SSH"
        
        if systemctl is-active --quiet ssh; then
            systemctl stop ssh
            print_success "SSH arrêté (MODE FORCÉ)"
            log_message "SSH arrêté en mode forcé"
        else
            print_warning "SSH déjà arrêté"
        fi
    }
fi

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi