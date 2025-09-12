#!/bin/bash

# =============================================================================
# RaspPunzel - Script de Mise à Jour du Système et des Outils
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

TOOLS_DIR="/opt/rasppunzel-tools"
BACKUP_DIR="/opt/backups/$(date +%Y%m%d_%H%M%S)"

# Vérification des privilèges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

# Banner
show_banner() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════╗"
    echo "║      RaspPunzel Update Manager        ║"
    echo "║    Mise à Jour Système et Outils      ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
}

# Sauvegarde des configurations
backup_configs() {
    print_status "Sauvegarde des configurations..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Sauvegarde des fichiers de configuration critiques
    cp -r /etc/hostapd "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/dnsmasq.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/nginx "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/network "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/wpa_supplicant "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /opt/rasppunzel-scripts "$BACKUP_DIR/" 2>/dev/null || true
    
    print_success "Configurations sauvegardées dans $BACKUP_DIR"
}

# Mise à jour du système de base
update_base_system() {
    print_status "Mise à jour du système de base..."
    
    # Ajouter les repos Kali si nécessaire
    if ! grep -q "kali-rolling" /etc/apt/sources.list; then
        echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
        print_status "Repository Kali ajouté"
    fi
    
    # Mise à jour des paquets
    apt-get update -qq
    
    # Mise à jour avec gestion des conflits
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade
    
    # Nettoyage
    apt-get autoremove -y -qq
    apt-get autoclean
    
    print_success "Système de base mis à jour"
}

# Mise à jour des outils Git
update_git_tools() {
    print_status "Mise à jour des outils Git..."
    
    if [ ! -d "$TOOLS_DIR" ]; then
        print_warning "Répertoire $TOOLS_DIR non trouvé"
        return
    fi
    
    cd "$TOOLS_DIR"
    
    # Liste des outils Git à mettre à jour
    local git_tools=(
        "wifipumpkin3"
        "wifiphisher" 
        "fluxion"
        "eaphammer"
        "airgeddon"
        "Empire"
        "social-engineer-toolkit"
        "theHarvester"
        "Sublist3r"
        "recon-ng"
        "XSStrike"
    )
    
    for tool in "${git_tools[@]}"; do
        if [ -d "$tool" ]; then
            print_status "Mise à jour de $tool..."
            cd "$tool"
            
            # Sauvegarder les changements locaux si nécessaire
            git stash save "Auto-stash avant mise à jour $(date)" 2>/dev/null || true
            
            # Mise à jour
            if git pull origin main 2>/dev/null || git pull origin master 2>/dev/null; then
                print_success "$tool mis à jour"
            else
                print_warning "Échec de la mise à jour de $tool"
            fi
            
            cd "$TOOLS_DIR"
        else
            print_warning "$tool non trouvé"
        fi
    done
}

# Mise à jour des outils Python
update_python_tools() {
    print_status "Mise à jour des outils Python..."
    
    # Mise à jour de pip
    pip3 install --upgrade pip
    
    # Outils Python à mettre à jour
    local python_tools=(
        "scapy"
        "requests"
        "beautifulsoup4"
        "selenium" 
        "paramiko"
        "pycryptodome"
        "netaddr"
        "dnspython"
        "python-nmap"
        "impacket"
        "crackmapexec"
        "ldap3"
        "flask"
        "socketio"
    )
    
    for tool in "${python_tools[@]}"; do
        print_status "Mise à jour de $tool..."
        pip3 install --upgrade --break-system-packages "$tool" 2>/dev/null || \
        pip3 install --upgrade "$tool" 2>/dev/null || \
        print_warning "Échec mise à jour $tool"
    done
    
    print_success "Outils Python mis à jour"
}

# Mise à jour de Metasploit
update_metasploit() {
    print_status "Mise à jour de Metasploit..."
    
    if command -v msfupdate &> /dev/null; then
        msfupdate
        print_success "Metasploit mis à jour"
    else
        print_warning "msfupdate non trouvé"
    fi
}

# Mise à jour des wordlists
update_wordlists() {
    print_status "Mise à jour des wordlists..."
    
    # SecLists
    if [ ! -d "/usr/share/seclists" ]; then
        print_status "Installation de SecLists..."
        cd /usr/share
        git clone https://github.com/danielmiessler/SecLists.git seclists
    else
        print_status "Mise à jour de SecLists..."
        cd /usr/share/seclists
        git pull
    fi
    
    # Rockyou si pas présent
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
        print_status "Installation de rockyou.txt..."
        cd /usr/share/wordlists
        if [ -f "rockyou.txt.gz" ]; then
            gunzip rockyou.txt.gz
        else
            wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
        fi
    fi
    
    print_success "Wordlists mis à jour"
}

# Mise à jour des signatures et bases de données
update_signatures() {
    print_status "Mise à jour des signatures et bases de données..."
    
    # Nmap scripts
    if command -v nmap &> /dev/null; then
        nmap --script-updatedb 2>/dev/null || print_warning "Échec mise à jour scripts Nmap"
    fi
    
    # John the Ripper
    if [ -d "/usr/share/john" ]; then
        cd /usr/share/john
        wget -q -N https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/password.lst 2>/dev/null || true
    fi
    
    print_success "Signatures mises à jour"
}

# Vérification de l'intégrité du système
check_system_integrity() {
    print_status "Vérification de l'intégrité du système..."
    
    local errors=0
    
    # Vérification des services critiques
    local services=("ssh" "nginx" "hostapd" "dnsmasq")
    for service in "${services[@]}"; do
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            print_warning "Service $service non activé"
            ((errors++))
        fi
    done
    
    # Vérification des fichiers de configuration
    local configs=(
        "/etc/hostapd/hostapd.conf"
        "/etc/dnsmasq.conf"
        "/etc/nginx/sites-available/rasppunzel"
    )
    
    for config in "${configs[@]}"; do
        if [ ! -f "$config" ]; then
            print_error "Fichier de configuration manquant: $config"
            ((errors++))
        fi
    done
    
    # Vérification des outils essentiels
    local tools=("nmap" "aircrack-ng" "john" "hashcat" "hydra")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "Outil manquant: $tool"
            ((errors++))
        fi
    done
    
    if [ $errors -eq 0 ]; then
        print_success "Intégrité du système OK"
    else
        print_warning "$errors problème(s) détecté(s)"
    fi
    
    return $errors
}

# Optimisation du système
optimize_system() {
    print_status "Optimisation du système..."
    
    # Nettoyage des logs anciens
    journalctl --vacuum-time=7d 2>/dev/null || true
    
    # Nettoyage des fichiers temporaires
    rm -rf /tmp/rasppunzel-* 2>/dev/null || true
    rm -rf /var/tmp/rasppunzel-* 2>/dev/null || true
    
    # Optimisation de la base de données locate
    updatedb &
    
    # Nettoyage des paquets orphelins
    apt-get autoremove --purge -y -qq
    
    # Vidage des caches
    sync && echo 3 > /proc/sys/vm/drop_caches
    
    print_success "Optimisation terminée"
}

# Redémarrage des services si nécessaire
restart_services_if_needed() {
    print_status "Vérification de la nécessité de redémarrer les services..."
    
    # Liste des services à vérifier
    local services=("hostapd" "dnsmasq" "nginx" "ssh")
    local restart_needed=false
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            if ! systemctl status "$service" | grep -q "active (running)"; then
                print_status "Redémarrage de $service nécessaire"
                systemctl restart "$service"
                restart_needed=true
            fi
        fi
    done
    
    if $restart_needed; then
        print_success "Services redémarrés"
    else
        print_status "Aucun redémarrage de service nécessaire"
    fi
}

# Affichage du résumé
show_update_summary() {
    print_status "Résumé de la mise à jour:"
    echo
    
    # Version du kernel
    print_status "Kernel: $(uname -r)"
    
    # Versions des outils principaux
    if command -v nmap &> /dev/null; then
        print_status "Nmap: $(nmap --version | head -1 | awk '{print $3}')"
    fi
    
    if command -v aircrack-ng &> /dev/null; then
        print_status "Aircrack-ng: $(aircrack-ng --help | head -1 | awk '{print $2}')"
    fi
    
    if command -v msfconsole &> /dev/null; then
        print_status "Metasploit: $(msfconsole --version | head -1)"
    fi
    
    # Espace disque
    print_status "Espace disque utilisé: $(df -h / | awk 'NR==2 {print $5}')"
    
    # Dernière mise à jour
    echo "$(date)" > /opt/rasppunzel-scripts/.last_update
    print_success "Dernière mise à jour: $(date)"
}

# Menu interactif
interactive_menu() {
    while true; do
        show_banner
        echo -e "${YELLOW}Options de mise à jour:${NC}"
        echo "1. Mise à jour complète (recommandé)"
        echo "2. Système de base uniquement"
        echo "3. Outils Git uniquement"
        echo "4. Outils Python uniquement"
        echo "5. Metasploit uniquement"
        echo "6. Wordlists uniquement"
        echo "7. Vérification d'intégrité"
        echo "8. Optimisation système"
        echo "9. Quitter"
        echo
        
        read -p "Votre choix [1-9]: " choice
        
        case $choice in
            1) full_update ;;
            2) update_base_system ;;
            3) update_git_tools ;;
            4) update_python_tools ;;
            5) update_metasploit ;;
            6) update_wordlists ;;
            7) check_system_integrity ;;
            8) optimize_system ;;
            9) break ;;
            *) print_error "Choix invalide" ;;
        esac
        
        echo
        read -p "Appuyez sur Entrée pour continuer..."
    done
}

# Mise à jour complète
full_update() {
    print_status "Début de la mise à jour complète..."
    
    backup_configs
    update_base_system
    update_git_tools
    update_python_tools
    update_metasploit
    update_wordlists
    update_signatures
    check_system_integrity
    optimize_system
    restart_services_if_needed
    show_update_summary
    
    print_success "Mise à jour complète terminée!"
}

# Fonction principale
main() {
    check_root
    
    case "${1:-menu}" in
        full|complete)
            full_update
            ;;
        system|base)
            backup_configs
            update_base_system
            ;;
        git)
            update_git_tools
            ;;
        python|py)
            update_python_tools
            ;;
        metasploit|msf)
            update_metasploit
            ;;
        wordlists)
            update_wordlists
            ;;
        check|verify)
            check_system_integrity
            ;;
        optimize)
            optimize_system
            ;;
        menu)
            interactive_menu
            ;;
        *)
            echo "Usage: $0 {full|system|git|python|metasploit|wordlists|check|optimize|menu}"
            echo
            echo "Commandes:"
            echo "  full       - Mise à jour complète (recommandé)"
            echo "  system     - Système de base uniquement"
            echo "  git        - Outils Git uniquement"
            echo "  python     - Outils Python uniquement"
            echo "  metasploit - Metasploit uniquement"
            echo "  wordlists  - Wordlists et dictionnaires"
            echo "  check      - Vérification d'intégrité"
            echo "  optimize   - Optimisation système"
            echo "  menu       - Menu interactif (défaut)"
            exit 1
            ;;
    esac
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi