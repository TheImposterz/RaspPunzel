#!/bin/bash

# -------------------------------------------------------------------------------------------------
# RaspPunzel - Installation Dashboard Web
# Script d'intégration pour la structure de projet existante
# -------------------------------------------------------------------------------------------------

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/rasppunzel"
WEB_DIR="$INSTALL_DIR/web"
PYTHON_ENV="$WEB_DIR/venv"
USER="pi"

# Fonctions utilitaires
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Ce script doit être exécuté en tant que root"
        echo "Utilisez: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    log_info "Vérification des dépendances..."
    
    local missing_deps=()
    
    for dep in python3 python3-pip python3-venv systemctl; do
        if ! command -v $dep &> /dev/null; then
            missing_deps+=($dep)
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_warning "Dépendances manquantes: ${missing_deps[*]}"
        log_info "Installation des dépendances..."
        apt-get update -qq
        apt-get install -y python3 python3-pip python3-venv systemd
    fi
    
    log_success "Dépendances vérifiées"
}

create_directories() {
    log_info "Création des répertoires..."
    
    mkdir -p "$WEB_DIR/api"
    mkdir -p "$WEB_DIR/assets"
    mkdir -p "/var/log/rasppunzel"
    
    log_success "Répertoires créés"
}

setup_python_environment() {
    log_info "Configuration de l'environnement Python..."
    
    # Créer l'environnement virtuel
    python3 -m venv "$PYTHON_ENV"
    
    # Mettre à jour pip
    "$PYTHON_ENV/bin/pip" install --upgrade pip
    
    # Installer les dépendances
    if [ -f "$PROJECT_ROOT/web/api/requirements.txt" ]; then
        "$PYTHON_ENV/bin/pip" install -r "$PROJECT_ROOT/web/api/requirements.txt"
    else
        log_warning "Fichier requirements.txt non trouvé, installation des dépendances de base"
        "$PYTHON_ENV/bin/pip" install Flask==3.0.0 Flask-CORS==4.0.0 Flask-SocketIO==5.3.6 psutil==5.9.5 python-socketio==5.9.0 eventlet==0.33.3
    fi
    
    log_success "Environnement Python configuré"
}

install_web_files() {
    log_info "Installation des fichiers web..."
    
    # Copier l'API
    if [ -f "$PROJECT_ROOT/web/api/app.py" ]; then
        cp "$PROJECT_ROOT/web/api/app.py" "$WEB_DIR/api/"
        log_success "API copiée"
    else
        log_error "Fichier app.py non trouvé dans $PROJECT_ROOT/web/api/"
        exit 1
    fi
    
    # Copier le dashboard
    if [ -f "$PROJECT_ROOT/web/dashboard.html" ]; then
        cp "$PROJECT_ROOT/web/dashboard.html" "$WEB_DIR/"
        log_success "Dashboard HTML copié"
    else
        log_error "Fichier dashboard.html non trouvé dans $PROJECT_ROOT/web/"
        exit 1
    fi
    
    # Copier les assets s'ils existent
    if [ -d "$PROJECT_ROOT/web/assets" ] && [ "$(ls -A $PROJECT_ROOT/web/assets)" ]; then
        cp -r "$PROJECT_ROOT/web/assets/"* "$WEB_DIR/assets/"
        log_success "Assets copiés"
    fi
    
    # Copier les requirements
    if [ -f "$PROJECT_ROOT/web/api/requirements.txt" ]; then
        cp "$PROJECT_ROOT/web/api/requirements.txt" "$WEB_DIR/api/"
    fi
}

setup_systemd_service() {
    log_info "Configuration du service systemd..."
    
    local service_file="/etc/systemd/system/rasppunzel-web.service"
    
    # Utiliser le fichier de service du projet s'il existe
    if [ -f "$PROJECT_ROOT/config/systemd/rasppunzel-web.service" ]; then
        cp "$PROJECT_ROOT/config/systemd/rasppunzel-web.service" "$service_file"
        log_success "Service systemd copié depuis le projet"
    else
        log_info "Création du service systemd..."
        cat > "$service_file" << EOF
[Unit]
Description=RaspPunzel Web Dashboard
Documentation=https://github.com/koutto/pi-pwnbox-rogueap
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$WEB_DIR
Environment=PATH=$PYTHON_ENV/bin
Environment=PYTHONPATH=$WEB_DIR
ExecStart=$PYTHON_ENV/bin/python api/app.py --host=0.0.0.0 --port=8080
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=5
Restart=always
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=3

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rasppunzel-web

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/rasppunzel
ReadOnlyPaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF
        log_success "Service systemd créé"
    fi
    
    # Recharger systemd et activer le service
    systemctl daemon-reload
    systemctl enable rasppunzel-web
    
    log_success "Service systemd configuré et activé"
}

set_permissions() {
    log_info "Configuration des permissions..."
    
    # Vérifier si l'utilisateur existe
    if ! id "$USER" &>/dev/null; then
        log_warning "Utilisateur $USER n'existe pas, utilisation de l'utilisateur actuel"
        USER=$(logname 2>/dev/null || echo $SUDO_USER || echo $USER)
    fi
    
    chown -R "$USER:$USER" "$WEB_DIR"
    chmod +x "$WEB_DIR/api/app.py"
    
    # Permissions pour les logs
    chown "$USER:$USER" "/var/log/rasppunzel"
    
    log_success "Permissions configurées"
}

integrate_with_existing_scripts() {
    log_info "Intégration avec les scripts existants..."
    
    # Modifier le script de démarrage s'il existe
    local start_script="$PROJECT_ROOT/scripts/start-services.sh"
    if [ -f "$start_script" ] && ! grep -q "rasppunzel-web" "$start_script"; then
        echo "" >> "$start_script"
        echo "# Dashboard web" >> "$start_script"
        echo "systemctl start rasppunzel-web" >> "$start_script"
        log_success "Dashboard ajouté au script de démarrage"
    fi
    
    # Modifier le script d'arrêt s'il existe
    local stop_script="$PROJECT_ROOT/scripts/stop-services.sh"
    if [ -f "$stop_script" ] && ! grep -q "rasppunzel-web" "$stop_script"; then
        sed -i '/systemctl stop/a systemctl stop rasppunzel-web' "$stop_script"
        log_success "Dashboard ajouté au script d'arrêt"
    fi
}

create_management_scripts() {
    log_info "Création des scripts de gestion..."
    
    # Script de démarrage spécifique au dashboard
    cat > "/usr/local/bin/rasppunzel-web-start" << 'EOF'
#!/bin/bash
set -e

echo "[+] Démarrage du dashboard web RaspPunzel..."

if ! systemctl is-active --quiet rasppunzel-web; then
    systemctl start rasppunzel-web
    sleep 2
fi

if systemctl is-active --quiet rasppunzel-web; then
    echo "[✓] Dashboard web démarré avec succès"
    echo "[i] Accessible sur :"
    echo "    http://$(hostname -I | awk '{print $1}'):8080"
    echo "    http://10.0.0.1:8080 (via point d'accès)"
else
    echo "[✗] Échec du démarrage du dashboard web"
    systemctl status rasppunzel-web --no-pager
    exit 1
fi
EOF

    # Script d'arrêt spécifique au dashboard
    cat > "/usr/local/bin/rasppunzel-web-stop" << 'EOF'
#!/bin/bash
set -e

echo "[+] Arrêt du dashboard web RaspPunzel..."

systemctl stop rasppunzel-web
pkill -f "rasppunzel.*app.py" 2>/dev/null || true

echo "[✓] Dashboard web arrêté"
EOF

    # Script de statut
    cat > "/usr/local/bin/rasppunzel-web-status" << 'EOF'
#!/bin/bash

echo "=== STATUS DASHBOARD WEB RASPPUNZEL ==="
echo

if systemctl is-active --quiet rasppunzel-web; then
    echo "Status: ACTIF"
    echo "URL: http://$(hostname -I | awk '{print $1}'):8080"
    echo "Logs: journalctl -u rasppunzel-web -f"
else
    echo "Status: INACTIF"
    echo "Démarrer avec: systemctl start rasppunzel-web"
fi

echo
echo "=== PROCESSUS ==="
ps aux | grep -E "(rasppunzel|app\.py)" | grep -v grep || echo "Aucun processus"

echo
echo "=== PORTS ==="
netstat -tlpn 2>/dev/null | grep :8080 || echo "Port 8080 non utilisé"
EOF

    # Rendre les scripts exécutables
    chmod +x /usr/local/bin/rasppunzel-web-*
    
    log_success "Scripts de gestion créés"
}

test_installation() {
    log_info "Test de l'installation..."
    
    # Test de démarrage
    systemctl start rasppunzel-web
    sleep 5
    
    if systemctl is-active --quiet rasppunzel-web; then
        log_success "Service démarré avec succès"
        
        # Test de connectivité
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "200\|404"; then
            log_success "Dashboard accessible sur le port 8080"
        else
            log_warning "Dashboard démarré mais non accessible via HTTP"
        fi
        
        systemctl stop rasppunzel-web
    else
        log_error "Échec du démarrage du service"
        journalctl -u rasppunzel-web --no-pager -n 10
        return 1
    fi
    
    log_success "Test d'installation réussi"
}

show_completion_message() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║             🎉 INSTALLATION TERMINÉE AVEC SUCCÈS 🎉             ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}📁 Installation:${NC}"
    echo "   • Répertoire: $WEB_DIR"
    echo "   • Service: rasppunzel-web"
    echo "   • Logs: /var/log/rasppunzel"
    echo
    echo -e "${YELLOW}🚀 Démarrage:${NC}"
    echo "   • make start-web"
    echo "   • systemctl start rasppunzel-web"
    echo "   • rasppunzel-web-start"
    echo
    echo -e "${YELLOW}🌐 Accès web:${NC}"
    echo "   • http://$(hostname -I | awk '{print $1}'):8080"
    echo "   • http://10.0.0.1:8080 (via point d'accès WiFi)"
    echo
    echo -e "${YELLOW}📊 Monitoring:${NC}"
    echo "   • make web-logs"
    echo "   • journalctl -u rasppunzel-web -f"
    echo "   • rasppunzel-web-status"
    echo
    echo -e "${YELLOW}🔧 Gestion:${NC}"
    echo "   • make status (statut général)"
    echo "   • make restart-web (redémarrage)"
    echo "   • make stop-web (arrêt)"
    echo
    echo -e "${GREEN}✅ Dashboard web RaspPunzel prêt à l'utilisation !${NC}"
}

# Fonction principale
main() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                  ║${NC}"
    echo -e "${BLUE}║              🚀 INSTALLATION DASHBOARD WEB RASPPUNZEL           ║${NC}"
    echo -e "${BLUE}║                                                                  ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Vérifications préalables
    check_root
    check_dependencies
    
    # Processus d'installation
    create_directories
    setup_python_environment
    install_web_files
    setup_systemd_service
    set_permissions
    integrate_with_existing_scripts
    create_management_scripts
    
    # Test et finalisation
    test_installation
    show_completion_message
}

# Gestion des arguments
case "${1:-}" in
    --check)
        check_dependencies
        echo "✅ Toutes les dépendances sont satisfaites"
        ;;
    --test)
        log_info "Test de l'installation existante..."
        if systemctl is-enabled --quiet rasppunzel-web 2>/dev/null; then
            test_installation
        else
            log_error "Service rasppunzel-web non installé"
            exit 1
        fi
        ;;
    --uninstall)
        log_warning "Désinstallation du dashboard web..."
        systemctl stop rasppunzel-web 2>/dev/null || true
        systemctl disable rasppunzel-web 2>/dev/null || true
        rm -f /etc/systemd/system/rasppunzel-web.service
        rm -rf "$WEB_DIR"
        rm -f /usr/local/bin/rasppunzel-web-*
        systemctl daemon-reload
        log_success "Dashboard web désinstallé"
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo
        echo "Options:"
        echo "  --check       Vérifier les dépendances"
        echo "  --test        Tester l'installation"
        echo "  --uninstall   Désinstaller le dashboard web"
        echo "  --help, -h    Afficher cette aide"
        echo
        echo "Installation normale: $0 (sans arguments)"
        ;;
    "")
        main
        ;;
    *)
        log_error "Option inconnue: $1"
        echo "Utilisez --help pour voir les options disponibles"
        exit 1
        ;;
esac