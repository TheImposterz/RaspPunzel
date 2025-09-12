#!/bin/bash

# =============================================================================
# RaspPunzel - Gestionnaire de Services
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

# Services principaux de l'implant
CORE_SERVICES=("ssh" "nginx" "hostapd" "dnsmasq")
OPTIONAL_SERVICES=("kismet" "tor" "mysql")

# Affichage du banner
show_banner() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════╗"
    echo "║     RaspPunzel Service Manager        ║"
    echo "║        Contrôle des Services          ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Fonction pour démarrer tous les services
start_all_services() {
    print_status "Démarrage de tous les services RaspPunzel..."
    
    for service in "${CORE_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_warning "$service est déjà démarré"
        else
            print_status "Démarrage de $service..."
            systemctl start "$service"
            if systemctl is-active --quiet "$service"; then
                print_success "$service démarré"
            else
                print_error "Échec du démarrage de $service"
            fi
        fi
    done
    
    # Vérification de la connectivité réseau
    sleep 3
    check_network_connectivity
}

# Fonction pour arrêter tous les services
stop_all_services() {
    print_status "Arrêt de tous les services RaspPunzel..."
    
    # Arrêt dans l'ordre inverse pour éviter les dépendances
    for service in "${CORE_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_status "Arrêt de $service..."
            systemctl stop "$service"
            print_success "$service arrêté"
        else
            print_warning "$service n'était pas démarré"
        fi
    done
}

# Fonction pour redémarrer tous les services
restart_all_services() {
    print_status "Redémarrage de tous les services..."
    stop_all_services
    sleep 2
    start_all_services
}

# Fonction pour afficher le statut des services
show_services_status() {
    print_status "Statut des services RaspPunzel:"
    echo
    
    for service in "${CORE_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            status="${GREEN}✓ ACTIF${NC}"
        else
            status="${RED}✗ ARRÊTÉ${NC}"
        fi
        printf "%-15s: %s\n" "$service" "$status"
    done
    
    echo
    print_status "Services optionnels:"
    for service in "${OPTIONAL_SERVICES[@]}"; do
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            if systemctl is-active --quiet "$service"; then
                status="${GREEN}✓ ACTIF${NC}"
            else
                status="${YELLOW}○ INACTIF${NC}"
            fi
        else
            status="${RED}✗ DÉSACTIVÉ${NC}"
        fi
        printf "%-15s: %s\n" "$service" "$status"
    done
}

# Vérification de la connectivité réseau
check_network_connectivity() {
    print_status "Vérification de la connectivité réseau..."
    
    # Test interface AP
    if ip addr show wlan1 | grep -q "192.168.10.1"; then
        print_success "Interface AP (wlan1) configurée: 192.168.10.1"
    else
        print_error "Interface AP non configurée correctement"
    fi
    
    # Test DHCP
    if systemctl is-active --quiet dnsmasq; then
        if ss -ulnp | grep -q ":67"; then
            print_success "Serveur DHCP actif sur port 67"
        else
            print_warning "Serveur DHCP ne semble pas écouter"
        fi
    fi
    
    # Test interface web
    if systemctl is-active --quiet nginx; then
        if ss -tlnp | grep -q ":8080"; then
            print_success "Interface web disponible sur port 8080"
        else
            print_warning "Interface web non accessible"
        fi
    fi
    
    # Test SSH
    if systemctl is-active --quiet ssh; then
        if ss -tlnp | grep -q ":22"; then
            print_success "SSH accessible sur port 22"
        else
            print_warning "SSH non accessible"
        fi
    fi
}

# Fonction pour démarrer le point d'accès
start_access_point() {
    print_status "Démarrage du point d'accès..."
    
    # Vérification de l'interface
    if ! ip link show wlan1 &>/dev/null; then
        print_error "Interface wlan1 non trouvée"
        return 1
    fi
    
    # Configuration de l'interface
    ip addr flush dev wlan1
    ip addr add 192.168.10.1/24 dev wlan1
    ip link set wlan1 up
    
    # Démarrage des services
    systemctl start hostapd
    systemctl start dnsmasq
    
    # Vérification
    sleep 3
    if systemctl is-active --quiet hostapd && systemctl is-active --quiet dnsmasq; then
        print_success "Point d'accès démarré"
        print_status "SSID: MAINTENANCE_WIFI (caché)"
        print_status "IP: 192.168.10.1"
    else
        print_error "Échec du démarrage du point d'accès"
    fi
}

# Fonction pour arrêter le point d'accès
stop_access_point() {
    print_status "Arrêt du point d'accès..."
    
    systemctl stop hostapd
    systemctl stop dnsmasq
    
    # Réinitialisation de l'interface
    if ip link show wlan1 &>/dev/null; then
        ip addr flush dev wlan1
        ip link set wlan1 down
    fi
    
    print_success "Point d'accès arrêté"
}

# Fonction pour gérer l'interface web
manage_web_interface() {
    case "$1" in
        start)
            print_status "Démarrage de l'interface web..."
            systemctl start nginx
            if systemctl is-active --quiet nginx; then
                print_success "Interface web démarrée sur http://192.168.10.1:8080"
            fi
            ;;
        stop)
            print_status "Arrêt de l'interface web..."
            systemctl stop nginx
            print_success "Interface web arrêtée"
            ;;
        restart)
            print_status "Redémarrage de l'interface web..."
            systemctl restart nginx
            print_success "Interface web redémarrée"
            ;;
        *)
            print_error "Usage: manage_web_interface {start|stop|restart}"
            ;;
    esac
}

# Menu interactif
interactive_menu() {
    while true; do
        show_banner
        show_services_status
        echo
        echo -e "${YELLOW}Actions disponibles:${NC}"
        echo "1. Démarrer tous les services"
        echo "2. Arrêter tous les services"
        echo "3. Redémarrer tous les services"
        echo "4. Démarrer le point d'accès uniquement"
        echo "5. Arrêter le point d'accès uniquement"
        echo "6. Gérer l'interface web"
        echo "7. Vérifier la connectivité"
        echo "8. Afficher les logs"
        echo "9. Quitter"
        echo
        
        read -p "Votre choix [1-9]: " choice
        
        case $choice in
            1) start_all_services ;;
            2) stop_all_services ;;
            3) restart_all_services ;;
            4) start_access_point ;;
            5) stop_access_point ;;
            6) 
                echo "Interface web: [s]tart [p]stop [r]estart"
                read -p "Action: " web_action
                case $web_action in
                    s) manage_web_interface start ;;
                    p) manage_web_interface stop ;;
                    r) manage_web_interface restart ;;
                esac
                ;;
            7) check_network_connectivity ;;
            8) show_logs ;;
            9) break ;;
            *) print_error "Choix invalide" ;;
        esac
        
        echo
        read -p "Appuyez sur Entrée pour continuer..."
    done
}

# Affichage des logs
show_logs() {
    print_status "Logs des services..."
    echo
    
    echo -e "${YELLOW}=== Logs Hostapd ===${NC}"
    tail -10 /var/log/syslog | grep hostapd || echo "Aucun log hostapd récent"
    
    echo -e "${YELLOW}=== Logs Dnsmasq ===${NC}"
    tail -10 /var/log/dnsmasq.log 2>/dev/null || echo "Aucun log dnsmasq"
    
    echo -e "${YELLOW}=== Logs Nginx ===${NC}"
    tail -10 /var/log/nginx/access.log 2>/dev/null || echo "Aucun log nginx"
    
    echo -e "${YELLOW}=== État des processus ===${NC}"
    ps aux | grep -E "(hostapd|dnsmasq|nginx)" | grep -v grep
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    case "${1:-menu}" in
        start)
            start_all_services
            ;;
        stop)
            stop_all_services
            ;;
        restart)
            restart_all_services
            ;;
        status)
            show_services_status
            ;;
        ap-start)
            start_access_point
            ;;
        ap-stop)
            stop_access_point
            ;;
        web)
            manage_web_interface "${2:-start}"
            ;;
        check)
            check_network_connectivity
            ;;
        logs)
            show_logs
            ;;
        menu)
            interactive_menu
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|ap-start|ap-stop|web|check|logs|menu}"
            echo
            echo "Commandes:"
            echo "  start     - Démarrer tous les services"
            echo "  stop      - Arrêter tous les services"
            echo "  restart   - Redémarrer tous les services"
            echo "  status    - Afficher le statut des services"
            echo "  ap-start  - Démarrer le point d'accès uniquement"
            echo "  ap-stop   - Arrêter le point d'accès uniquement"
            echo "  web       - Gérer l'interface web"
            echo "  check     - Vérifier la connectivité"
            echo "  logs      - Afficher les logs"
            echo "  menu      - Menu interactif (défaut)"
            exit 1
            ;;
    esac
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi