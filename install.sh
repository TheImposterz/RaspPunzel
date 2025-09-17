#!/bin/bash

# =============================================================================
# RaspPunzel - Installation Script v1.0
# Implant RedTeam portable pour Raspberry Pi
# =============================================================================

set -e

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration par défaut
DEFAULT_ADMIN_USER="admin"
DEFAULT_ADMIN_PASS="RedTeam2024!"
DEFAULT_WIFI_SSID="MAINTENANCE_WIFI"
DEFAULT_WIFI_PASS="SecureP@ss123!"
DEFAULT_AP_IP="192.168.10.1"
DEFAULT_WEB_PORT="8080"

# Variables globales pour la configuration
ADMIN_USER=""
ADMIN_PASS=""
WIFI_SSID=""
WIFI_PASS=""
AP_IP=""
WEB_PORT=""

# Fonction d'affichage améliorées
print_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                        🚀 RaspPunzel 🚀                      ║
║                                                              ║
║            Implant RedTeam portable pour Raspberry Pi       ║
║                     Installation v1.0                       ║
╚══════════════════════════════════════════════════════════════╝
by @bl4ckarch
EOF
    echo -e "${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Vérifications préliminaires
check_prerequisites() {
    print_step "Vérification des prérequis..."
    
    # Vérification des privilèges root
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        echo "Utilisez: sudo $0"
        exit 1
    fi
    
    # Vérification de la plateforme
    if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        print_warning "Système non détecté comme Raspberry Pi"
        read -p "Continuer quand même? (y/N): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
    
    # Vérification de l'espace disque (minimum 4GB libre)
    local free_space=$(df / | awk 'NR==2 {print $4}')
    if [ $free_space -lt 4194304 ]; then  # 4GB en KB
        print_warning "Espace disque faible (moins de 4GB libre)"
        print_status "Espace libre: $(( free_space / 1024 / 1024 ))GB"
    fi
    
    # Vérification de la connexion Internet
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        print_error "Connexion Internet requise pour l'installation"
        exit 1
    fi
    
    print_success "Prérequis validés"
}

# Installation des packages de base nécessaires
install_base_packages() {
    print_step "Installation des packages système de base..."
    
    # Mise à jour de la liste des packages
    apt-get update -qq || {
        print_error "Impossible de mettre à jour la liste des packages"
        return 1
    }
    
    # Packages essentiels pour le fonctionnement de RaspPunzel
    local base_packages=(
        "hostapd"
        "dnsmasq" 
        "nginx"
        "openssh-server"
        "python3"
        "python3-pip"
        "curl"
        "wget"
        "systemd"
        "iproute2"
        "iptables"
    )
    
    print_status "Installation des packages essentiels..."
    for package in "${base_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            print_status "Installation de $package..."
            if apt-get install -y -qq "$package"; then
                print_success "$package installé"
            else
                print_warning "Échec installation $package (non critique)"
            fi
        else
            print_status "$package déjà installé"
        fi
    done
    
    # Vérification que les services critiques peuvent démarrer
    print_status "Vérification des services..."
    
    # Arrêt des services pour éviter les conflits pendant la configuration
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    
    print_success "Packages de base installés et services préparés"
}

# Fonction à appeler AVANT apply_configuration() dans main()
check_and_create_directories() {
    print_step "Vérification de la structure des répertoires..."
    
    # Vérification que le script est lancé depuis le bon répertoire
    if [ ! -d "config" ]; then
        print_error "Répertoire 'config' non trouvé. Lancez le script depuis le répertoire d'installation."
        return 1
    fi
    
    # Création de tous les répertoires nécessaires
    local directories=(
        "/opt/rasppunzel/web"
        "/opt/rasppunzel/config"
        "/opt/rasppunzel-scripts"
        "/var/log/rasppunzel"
        "/etc/hostapd"
        "/etc/nginx/sites-available"
        "/etc/nginx/sites-enabled"
    )
    
    for dir in "${directories[@]}"; do
        if ! mkdir -p "$dir"; then
            print_error "Impossible de créer le répertoire $dir"
            return 1
        fi
    done
    
    # Vérification des templates requis
    local required_templates=(
        "config/network/hostapd.conf.template"
        "config/network/dnsmasq.conf.template"
        "config/network/interfaces.template"
        "config/services/nginx-rasppunzel.conf"
    )
    
    local missing_templates=()
    for template in "${required_templates[@]}"; do
        if [ ! -f "$template" ]; then
            missing_templates+=("$template")
        fi
    done
    
    if [ ${#missing_templates[@]} -gt 0 ]; then
        print_warning "Templates manquants détectés:"
        for missing in "${missing_templates[@]}"; do
            echo "  - $missing"
        done
        print_warning "Installation continuera mais certaines fonctionnalités pourraient ne pas être disponibles"
    fi
    
    print_success "Structure des répertoires vérifiée"
}
# Configuration interactive avec validation
configure_settings() {
    print_step "Configuration interactive de RaspPunzel"
    echo
    
    # Configuration utilisateur admin
    while true; do
        read -p "Nom d'utilisateur admin [$DEFAULT_ADMIN_USER]: " ADMIN_USER
        ADMIN_USER=${ADMIN_USER:-$DEFAULT_ADMIN_USER}
        if [[ $ADMIN_USER =~ ^[a-zA-Z0-9_-]{3,20}$ ]]; then
            break
        else
            print_error "Nom d'utilisateur invalide (3-20 caractères, lettres/chiffres/_/- uniquement)"
        fi
    done
    
    # Configuration mot de passe admin avec validation
    while true; do
        echo -n "Mot de passe admin (8+ caractères) [$DEFAULT_ADMIN_PASS]: "
        read -s ADMIN_PASS
        ADMIN_PASS=${ADMIN_PASS:-$DEFAULT_ADMIN_PASS}
        echo
        if [ ${#ADMIN_PASS} -ge 8 ]; then
            echo -n "Confirmer le mot de passe: "
            read -s ADMIN_PASS_CONFIRM
            echo
            if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ]; then
                break
            else
                print_error "Les mots de passe ne correspondent pas"
            fi
        else
            print_error "Mot de passe trop court (minimum 8 caractères)"
        fi
    done
    
    # Configuration WiFi SSID
    while true; do
        read -p "SSID du WiFi caché [$DEFAULT_WIFI_SSID]: " WIFI_SSID
        WIFI_SSID=${WIFI_SSID:-$DEFAULT_WIFI_SSID}
        if [ ${#WIFI_SSID} -le 32 ] && [ ${#WIFI_SSID} -ge 1 ]; then
            break
        else
            print_error "SSID invalide (1-32 caractères)"
        fi
    done
    
    # Configuration mot de passe WiFi
    while true; do
        echo -n "Mot de passe WiFi (8+ caractères) [$DEFAULT_WIFI_PASS]: "
        read -s WIFI_PASS
        WIFI_PASS=${WIFI_PASS:-$DEFAULT_WIFI_PASS}
        echo
        if [ ${#WIFI_PASS} -ge 8 ] && [ ${#WIFI_PASS} -le 63 ]; then
            break
        else
            print_error "Mot de passe WiFi invalide (8-63 caractères)"
        fi
    done
    
    # Configuration IP avec validation
    while true; do
        read -p "IP du point d'accès [$DEFAULT_AP_IP]: " AP_IP
        AP_IP=${AP_IP:-$DEFAULT_AP_IP}
        if [[ $AP_IP =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            break
        else
            print_error "IP invalide (format: 192.168.x.x)"
        fi
    done
    
    # Configuration port web
    while true; do
        read -p "Port interface web [$DEFAULT_WEB_PORT]: " WEB_PORT
        WEB_PORT=${WEB_PORT:-$DEFAULT_WEB_PORT}
        if [[ $WEB_PORT =~ ^[0-9]+$ ]] && [ $WEB_PORT -ge 1024 ] && [ $WEB_PORT -le 65535 ]; then
            break
        else
            print_error "Port invalide (1024-65535)"
        fi
    done
    
    echo
    print_success "Configuration enregistrée"
    
    # Résumé de la configuration
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Résumé de la configuration:${NC}"
    echo "   Utilisateur admin: $ADMIN_USER"
    echo "   SSID WiFi: $WIFI_SSID (caché)"
    echo "   IP point d'accès: $AP_IP"
    echo "   Port web: $WEB_PORT"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    
    read -p "Confirmer la configuration? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_warning "Configuration annulée"
        exit 0
    fi
}

# Application de la configuration aux templates
# Application de la configuration aux templates
apply_configuration() {
    print_step "Application de la configuration..."
    
    # Création des répertoires nécessaires pour RaspPunzel
    mkdir -p /opt/rasppunzel/web
    mkdir -p /opt/rasppunzel/config
    mkdir -p /opt/rasppunzel-scripts
    mkdir -p /var/log/rasppunzel
    
    # Création des répertoires système nécessaires
    mkdir -p /etc/hostapd
    mkdir -p /etc/nginx/sites-available
    mkdir -p /etc/nginx/sites-enabled
    
    # Application de la configuration aux templates réseau
    if [ -f "config/network/hostapd.conf.template" ]; then
        sed "s/MAINTENANCE_WIFI/$WIFI_SSID/g; s/SecureP@ss123!/$WIFI_PASS/g" \
            config/network/hostapd.conf.template > /etc/hostapd/hostapd.conf
        # Vérification que le fichier a été créé
        if [ -f "/etc/hostapd/hostapd.conf" ]; then
            print_success "Configuration hostapd appliquée"
        else
            print_error "Échec création fichier hostapd.conf"
            return 1
        fi
    else
        print_warning "Template hostapd.conf.template non trouvé"
    fi
    
    if [ -f "config/network/dnsmasq.conf.template" ]; then
        # Sauvegarde de la configuration originale si elle existe
        if [ -f "/etc/dnsmasq.conf" ]; then
            cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
        fi
        sed "s/192\.168\.10\.1/$AP_IP/g" \
            config/network/dnsmasq.conf.template > /etc/dnsmasq.conf
        # Vérification que le fichier a été créé
        if [ -f "/etc/dnsmasq.conf" ]; then
            print_success "Configuration dnsmasq appliquée"
        else
            print_error "Échec création fichier dnsmasq.conf"
            return 1
        fi
    else
        print_warning "Template dnsmasq.conf.template non trouvé"
    fi
    
    if [ -f "config/network/interfaces.template" ]; then
        # Sauvegarde de la configuration originale
        if [ -f "/etc/network/interfaces" ]; then
            cp /etc/network/interfaces /etc/network/interfaces.backup
        fi
        sed "s/192\.168\.10\.1/$AP_IP/g" \
            config/network/interfaces.template > /etc/network/interfaces.new
        print_success "Configuration interfaces préparée (sera appliquée plus tard)"
    else
        print_warning "Template interfaces.template non trouvé"
    fi
    
    # Configuration nginx
    if [ -f "config/services/nginx-rasppunzel.conf" ]; then
        sed "s/8080/$WEB_PORT/g" \
            config/services/nginx-rasppunzel.conf > /etc/nginx/sites-available/rasppunzel
        # Vérification que le fichier a été créé
        if [ -f "/etc/nginx/sites-available/rasppunzel" ]; then
            print_success "Configuration nginx appliquée"
        else
            print_error "Échec création fichier nginx"
            return 1
        fi
    else
        print_warning "Template nginx-rasppunzel.conf non trouvé"
    fi
    
    print_success "Configuration appliquée aux templates"
}
# Créer le fichier de configuration d'authentification
create_auth_config() {
    print_step "Configuration de l'authentification..."
    
    mkdir -p /opt/rasppunzel/config
    
    # Hash du mot de passe avec Python
    PASSWORD_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('$ADMIN_PASS'.encode()).hexdigest())")
    
    cat > /opt/rasppunzel/config/auth.json << EOF
{
    "username": "$ADMIN_USER",
    "password_hash": "$PASSWORD_HASH",
    "created_at": "$(date -I)",
    "session_timeout": 480
}
EOF
    
    chmod 600 /opt/rasppunzel/config/auth.json
    chown $ADMIN_USER:$ADMIN_USER /opt/rasppunzel/config/auth.json 2>/dev/null || true
    
    print_success "Configuration d'authentification créée"
}

# Copie des fichiers de configuration
copy_configurations() {
    print_step "Copie des fichiers de configuration..."
    
    # Copie des scripts avec permissions
    if [ -d "scripts" ]; then
        cp -r scripts/* /opt/rasppunzel-scripts/
        chmod +x /opt/rasppunzel-scripts/*.sh
        print_success "Scripts copiés et rendus exécutables"
    fi
    
    # Copie de l'interface web
    if [ -f "web/dashboard.html" ]; then
        cp web/dashboard.html /opt/rasppunzel/web/
        print_success "Interface web copiée"
    fi
    
    if [ -f "web/login.html" ]; then
        cp web/login.html /opt/rasppunzel/web/
        print_success "Page de login copiée"
    fi
    
    # Copie de l'API
    if [ -d "web/api" ]; then
        cp -r web/api /opt/rasppunzel/web/
        print_success "API copiée"
    fi
    
    # Copie des services systemd
    if [ -f "config/systemd/rasppunzel-tower.service" ]; then
        cp config/systemd/rasppunzel-tower.service /etc/systemd/system/
        systemctl daemon-reload
        print_success "Service systemd installé"
    fi
    
    if [ -f "config/systemd/rasppunzel-network.service" ]; then
        cp config/systemd/rasppunzel-network.service /etc/systemd/system/
        print_success "Service réseau systemd installé"
    fi
}

# Configuration des services système
setup_services() {
    print_step "Configuration des services système..."
    
    # Service SSH avec configuration sécurisée
    systemctl enable ssh
    
    # Application de la configuration SSH si disponible
    if [ -f "config/services/ssh-config.template" ]; then
        cp config/services/ssh-config.template /etc/ssh/sshd_config.rasppunzel
        print_status "Configuration SSH de référence créée"
    fi
    
    # Configuration SSH de base
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # Création de l'utilisateur admin
    if ! id "$ADMIN_USER" &>/dev/null; then
        useradd -m -s /bin/bash "$ADMIN_USER"
        echo "$ADMIN_USER:$ADMIN_PASS" | chpasswd
        usermod -aG sudo "$ADMIN_USER"
        
        # Création du répertoire SSH pour l'utilisateur
        mkdir -p /home/$ADMIN_USER/.ssh
        chmod 700 /home/$ADMIN_USER/.ssh
        chown $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER/.ssh
        
        print_success "Utilisateur '$ADMIN_USER' créé avec privilèges sudo"
    else
        print_warning "L'utilisateur '$ADMIN_USER' existe déjà"
    fi
    
    # Configuration de l'auto-login console
    mkdir -p /etc/systemd/system/getty@tty1.service.d/
    cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf << EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $ADMIN_USER --noclear %I \$TERM
EOF
    
    # Configuration nginx
    if [ -f "/etc/nginx/sites-available/rasppunzel" ]; then
        ln -sf /etc/nginx/sites-available/rasppunzel /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
        systemctl enable nginx
        print_success "Configuration nginx activée"
    fi
    
    print_success "Services système configurés"
}

# Activation des services de démarrage automatique
setup_autostart() {
    print_step "Configuration du démarrage automatique..."
    
    # Activation des services systemd
    systemctl enable rasppunzel-tower.service 2>/dev/null || print_warning "Service rasppunzel-tower non trouvé"
    systemctl enable rasppunzel-network.service 2>/dev/null || print_warning "Service rasppunzel-network non trouvé"
    
    # Création d'un service de fallback si les services principaux n'existent pas
    if [ ! -f "/etc/systemd/system/rasppunzel-tower.service" ]; then
        cat > /etc/systemd/system/rasppunzel-fallback.service << EOF
[Unit]
Description=RaspPunzel Fallback Service
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/opt/rasppunzel-scripts/start-services.sh
ExecStop=/opt/rasppunzel-scripts/stop-services.sh
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable rasppunzel-fallback.service
        print_success "Service de fallback créé et activé"
    fi
    
    print_success "Démarrage automatique configuré"
}

# Création d'un script de status system
create_status_script() {
    print_step "Création des outils de diagnostic..."
    
    cat > /usr/local/bin/rasppunzel-status << 'EOF'
#!/bin/bash
# Script de status RaspPunzel

echo "RaspPunzel Status Dashboard"
echo "=========================="
echo
echo "Services Status:"
systemctl is-active --quiet ssh && echo "  SSH: Active" || echo "  SSH: Inactive"
systemctl is-active --quiet hostapd && echo "  hostapd: Active" || echo "  hostapd: Inactive"
systemctl is-active --quiet dnsmasq && echo "  dnsmasq: Active" || echo "  dnsmasq: Inactive"
systemctl is-active --quiet nginx && echo "  nginx: Active" || echo "  nginx: Inactive"

echo
echo "Network Status:"
ip addr show | grep "inet " | grep -v "127.0.0.1" | while read line; do
    echo "  $line"
done

echo
echo "System Resources:"
echo "  Uptime: $(uptime -p)"
echo "  Disk Usage: $(df -h / | awk 'NR==2 {print $5 " used"}')"
echo "  Memory: $(free -h | awk 'NR==2{printf "%.1fG/%.1fG (%.0f%%)\n", $3/1024, $2/1024, $3*100/$2}')"
echo "  Temperature: $(vcgencmd measure_temp 2>/dev/null || echo "N/A")"

echo
echo "Access Information:"
echo "  Web Interface: http://$(hostname -I | awk '{print $1}'):8080"
echo "  SSH: ssh admin@$(hostname -I | awk '{print $1}')"
EOF
    
    chmod +x /usr/local/bin/rasppunzel-status
    
    # Alias dans bashrc
    echo "alias rpstatus='rasppunzel-status'" >> /home/$ADMIN_USER/.bashrc 2>/dev/null || true
    
    print_success "Script de diagnostic créé (/usr/local/bin/rasppunzel-status)"
}

# Nettoyage et optimisation finale
cleanup_and_optimize() {
    print_step "Nettoyage et optimisation finale..."
    
    # Nettoyage APT
    apt-get autoremove -y -qq
    apt-get autoclean -qq
    
    # Optimisation des logs
    mkdir -p /var/log/rasppunzel
    touch /var/log/rasppunzel/access.log
    touch /var/log/rasppunzel/install.log
    
    # Log de l'installation
    echo "[$(date)] RaspPunzel installation completed successfully" >> /var/log/rasppunzel/install.log
    
    # Optimisation des permissions
    chown -R $ADMIN_USER:$ADMIN_USER /home/$ADMIN_USER 2>/dev/null || true
    chown -R $ADMIN_USER:$ADMIN_USER /opt/rasppunzel 2>/dev/null || true
    chmod -R 755 /opt/rasppunzel-scripts
    chmod 644 /var/log/rasppunzel/*.log
    
    # Nettoyage des fichiers temporaires
    rm -rf /tmp/rasppunzel-* 2>/dev/null || true
    
    print_success "Nettoyage et optimisation terminés"
}
# Installation complète avec gestion d'erreur


# Installation complète avec gestion d'erreur
main() {
    # Gestion des erreurs
    trap 'print_error "Installation échouée à la ligne $LINENO. Consultez /var/log/rasppunzel/install.log"' ERR
    
    clear
    print_banner
    
    print_status "Démarrage de l'installation RaspPunzel v1.0"
    print_status "Temps estimé: 10-15 minutes selon votre connexion Internet"
    echo
    
    # Étapes d'installation dans l'ordre correct
    check_prerequisites
    configure_settings
    
    # NOUVEAU: Installation des packages de base AVANT la configuration
    install_base_packages || {
        print_error "Installation des packages de base échouée"
        exit 1
    }
    
    # NOUVEAU: Vérification des répertoires AVANT apply_configuration
    check_and_create_directories || {
        print_error "Vérification des répertoires échouée" 
        exit 1
    }
    
    apply_configuration || {
        print_error "Application de la configuration échouée"
        exit 1
    }
    
    create_auth_config
    
    # Exécution des sous-scripts avec vérification
    print_step "Exécution des scripts de configuration..."
    
    if [ -f "scripts/update-system.sh" ]; then
        print_status "Mise à jour du système..."
        bash scripts/update-system.sh || print_warning "Mise à jour système échouée (non critique)"
    fi
    
    if [ -f "scripts/setup-tools.sh" ]; then
        print_status "Installation des outils de pentest..."
        bash scripts/setup-tools.sh || print_warning "Installation d'outils échouée (non critique)"
    fi
    
    if [ -f "scripts/install-web-dashboard.sh" ]; then
        print_status "Installation du dashboard web..."
        bash scripts/install-web-dashboard.sh || print_error "Installation dashboard web échouée (critique)"
    else
        print_warning "Script install-web-dashboard.sh non trouvé - Interface web non disponible"
    fi
    
    if [ -f "scripts/setup-network.sh" ]; then
        print_status "Configuration réseau..."
        bash scripts/setup-network.sh || print_error "Configuration réseau échouée (critique)"
    fi
    
    copy_configurations
    setup_services
    setup_autostart
    create_status_script
    cleanup_and_optimize
    
    # Le reste du code reste identique...
    # [Résumé final]
    # Résumé final
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    INSTALLATION RÉUSSIE                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    print_success "RaspPunzel v1.0 installé avec succès!"
    print_warning "REDÉMARRAGE REQUIS pour finaliser l'installation"
    echo
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Informations d'accès après redémarrage:${NC}"
    echo
    echo "   WiFi AP (caché): $WIFI_SSID"
    echo "   Mot de passe WiFi: [CONFIGURÉ]"
    echo "   IP du Pi: $AP_IP"
    echo "   Interface Web: http://$AP_IP:$WEB_PORT"
    echo "   Login web: $ADMIN_USER / [MOT DE PASSE CONFIGURÉ]"
    echo "   SSH: ssh $ADMIN_USER@$AP_IP"
    echo
    echo -e "${YELLOW}Commandes utiles:${NC}"
    echo "   rasppunzel-status  # Status du système"
    echo
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    
    # Proposition de redémarrage
    read -p "Redémarrer maintenant pour finaliser l'installation? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo
        print_warning "N'oubliez pas de redémarrer plus tard avec: sudo reboot"
        print_status "Installation terminée. Redémarrage manuel requis."
    else
        echo
        print_status "Redémarrage en cours..."
        sleep 2
        reboot
    fi
}

# Point d'entrée avec gestion des arguments
case "${1:-install}" in
    install|"")
        main "$@"
        ;;
    --help|-h)
        echo "RaspPunzel Installation Script v1.0"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  install, (default)  Installation complète interactive"
        echo "  --help, -h          Afficher cette aide"
        echo "  --version, -v       Afficher la version"
        echo
        ;;
    --version|-v)
        echo "RaspPunzel Installation Script v1.0"
        echo "Implant RedTeam portable pour Raspberry Pi"
        ;;
    *)
        print_error "Option inconnue: $1"
        echo "Utilisez: $0 --help pour voir les options disponibles"
        exit 1
        ;;
esac