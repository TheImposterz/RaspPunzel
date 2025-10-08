#!/bin/bash

# =================================================================================================
# RaspPunzel - Ligolo-ng Unified Installation & Configuration
# =================================================================================================
# Installation complète : Agent + Configuration + Certificats
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Fichiers de configuration
CONFIG_DIR="/etc/rasppunzel"
CONFIG_FILE="${CONFIG_DIR}/ligolo.conf"
LOG_FILE="${CONFIG_DIR}/ligolo-install.log"
CERTS_DIR="${CONFIG_DIR}/certs"

# Version Ligolo
LIGOLO_VERSION="v0.8.2"

# =================================================================================================
# Fonction de logging
# =================================================================================================

log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}[INFO]${NC} $@"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[✓]${NC} $@"
}

log_warning() {
    log "WARNING" "$@"
    echo -e "${YELLOW}[!]${NC} $@"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[✗]${NC} $@"
}

# =================================================================================================
# Vérifications préliminaires
# =================================================================================================

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  RaspPunzel - Installation Ligolo-ng${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   log_error "Ce script doit être exécuté en tant que root"
   exit 1
fi

# Créer les répertoires
mkdir -p "$CONFIG_DIR" "$CERTS_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

log_info "Début de l'installation - Version Ligolo: ${LIGOLO_VERSION}"

# Détecter l'architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        LIGOLO_ARCH="amd64"
        ;;
    aarch64|arm64)
        LIGOLO_ARCH="arm64"
        ;;
    armv7l|armv6l)
        LIGOLO_ARCH="armv7"
        ;;
    *)
        log_error "Architecture non supportée: $ARCH"
        exit 1
        ;;
esac

log_info "Architecture détectée: ${ARCH} (Ligolo: ${LIGOLO_ARCH})"

# =================================================================================================
# ÉTAPE 1 : Installation de l'agent Ligolo-ng
# =================================================================================================

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 1/3 - Installation de l'agent Ligolo-ng              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Vérifier si déjà installé
if [ -f "/usr/local/bin/ligolo-agent" ]; then
    CURRENT_VERSION=$(/usr/local/bin/ligolo-agent --version 2>&1 | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    log_warning "Agent déjà installé (${CURRENT_VERSION})"
    read -p "Voulez-vous réinstaller? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation de l'agent ignorée"
        SKIP_AGENT_INSTALL=true
    else
        SKIP_AGENT_INSTALL=false
    fi
else
    SKIP_AGENT_INSTALL=false
fi

if [ "$SKIP_AGENT_INSTALL" = false ]; then
    log_info "Téléchargement de l'agent Ligolo-ng..."
    
    LIGOLO_URL="https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_${LIGOLO_ARCH}.tar.gz"
    
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR"
    
    # Téléchargement avec retries
    MAX_RETRIES=3
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if wget --timeout=30 --tries=3 -q --show-progress "${LIGOLO_URL}" -O ligolo-agent.tar.gz 2>&1 | tee -a "$LOG_FILE"; then
            log_success "Téléchargement réussi"
            break
        else
            RETRY_COUNT=$((RETRY_COUNT + 1))
            if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
                log_warning "Échec du téléchargement, nouvelle tentative ($RETRY_COUNT/$MAX_RETRIES)..."
                sleep 3
            else
                log_error "Échec après $MAX_RETRIES tentatives"
                log_error "URL: ${LIGOLO_URL}"
                rm -rf "$TMP_DIR"
                exit 1
            fi
        fi
    done
    
    # Extraction
    log_info "Extraction de l'archive..."
    if ! tar -xzf ligolo-agent.tar.gz 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Échec de l'extraction"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    
    # Trouver le binaire
    AGENT_BINARY=$(find . -name "agent" -type f | head -n 1)
    
    if [ -z "$AGENT_BINARY" ] || [ ! -f "$AGENT_BINARY" ]; then
        log_error "Binaire agent introuvable dans l'archive"
        tar -tzf ligolo-agent.tar.gz | tee -a "$LOG_FILE"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    
    # Installation
    log_info "Installation du binaire..."
    install -m 0755 "$AGENT_BINARY" /usr/local/bin/ligolo-agent
    
    if [ ! -f "/usr/local/bin/ligolo-agent" ]; then
        log_error "Échec de l'installation du binaire"
        rm -rf "$TMP_DIR"
        exit 1
    fi
    
    rm -rf "$TMP_DIR"
    
    # Vérification
    if /usr/local/bin/ligolo-agent --version >/dev/null 2>&1; then
        log_success "Agent installé: $(/usr/local/bin/ligolo-agent --version 2>&1 | head -1)"
    else
        log_error "Le binaire ne fonctionne pas correctement"
        exit 1
    fi
fi

# =================================================================================================
# ÉTAPE 2 : Configuration de l'agent
# =================================================================================================

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 2/3 - Configuration de l'agent                       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Charger la config existante si présente
if [ -f "$CONFIG_FILE" ]; then
    log_warning "Configuration existante trouvée"
    source "$CONFIG_FILE"
    echo ""
    echo -e "${CYAN}Configuration actuelle:${NC}"
    echo -e "  Proxy: ${LIGOLO_PROXY_HOST:-Non défini}:${LIGOLO_PROXY_PORT:-Non défini}"
    echo -e "  Mode: ${LIGOLO_USE_CERTS:-false}"
    echo ""
    read -p "Reconfigurer? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Configuration existante conservée"
        SKIP_CONFIG=true
    else
        SKIP_CONFIG=false
    fi
else
    SKIP_CONFIG=false
fi

if [ "$SKIP_CONFIG" = false ]; then
    # Configuration du proxy
    log_info "Configuration de la connexion proxy..."
    echo ""
    
    while true; do
        read -p "Adresse IP/Hostname du proxy: " PROXY_HOST
        if [ -n "$PROXY_HOST" ]; then
            log_info "Proxy Host: ${PROXY_HOST}"
            break
        fi
        log_error "L'adresse du proxy est requise"
    done
    
    while true; do
        read -p "Port du proxy [443]: " PROXY_PORT
        PROXY_PORT=${PROXY_PORT:-443}
        if [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && [ "$PROXY_PORT" -ge 1 ] && [ "$PROXY_PORT" -le 65535 ]; then
            log_info "Proxy Port: ${PROXY_PORT}"
            break
        fi
        log_error "Port invalide (1-65535)"
    done
    
    # Mode de connexion
    echo ""
    echo -e "${CYAN}Mode de connexion:${NC}"
    echo -e "  1) Auto-signé (ignorer les certificats) - ${GREEN}Rapide${NC}"
    echo -e "  2) Certificats personnalisés - ${YELLOW}Sécurisé${NC}"
    echo ""
    
    while true; do
        read -p "Choisir le mode [1]: " CERT_MODE
        CERT_MODE=${CERT_MODE:-1}
        
        case $CERT_MODE in
            1)
                USE_CERTS="false"
                IGNORE_CERT="true"
                log_info "Mode: Auto-signé (ignore-cert activé)"
                break
                ;;
            2)
                USE_CERTS="true"
                IGNORE_CERT="false"
                log_info "Mode: Certificats personnalisés"
                break
                ;;
            *)
                log_error "Choix invalide (1 ou 2)"
                ;;
        esac
    done
    
    # Options de reconnexion
    echo ""
    read -p "Reconnexion automatique? (Y/n): " AUTO_RETRY
    AUTO_RETRY=${AUTO_RETRY:-Y}
    if [[ ${AUTO_RETRY^^} =~ ^Y|YES$ ]]; then
        RETRY="true"
        read -p "Délai de reconnexion (secondes) [10]: " RETRY_DELAY
        RETRY_DELAY=${RETRY_DELAY:-10}
        log_info "Auto-retry activé (${RETRY_DELAY}s)"
    else
        RETRY="false"
        RETRY_DELAY="10"
        log_info "Auto-retry désactivé"
    fi
    
    # Test de connexion
    echo ""
    read -p "Tester la connexion? (y/N): " TEST_CONN
    if [[ ${TEST_CONN^^} =~ ^Y|YES$ ]]; then
        log_info "Test de connexion vers ${PROXY_HOST}:${PROXY_PORT}..."
        if timeout 5 bash -c "echo > /dev/tcp/${PROXY_HOST}/${PROXY_PORT}" 2>/dev/null; then
            log_success "Connexion réussie!"
        else
            log_warning "Impossible de se connecter"
            log_warning "Causes possibles: proxy non démarré, firewall, réseau"
            read -p "Continuer quand même? (y/N): " CONTINUE
            if [[ ! ${CONTINUE^^} =~ ^Y|YES$ ]]; then
                log_error "Configuration annulée"
                exit 1
            fi
        fi
    fi
    
    # Sauvegarder la configuration
    log_info "Sauvegarde de la configuration..."
    
    cat > "$CONFIG_FILE" <<EOF
# RaspPunzel - Ligolo-ng Configuration
# Généré le: $(date)
# Log: ${LOG_FILE}

# Connexion proxy
LIGOLO_PROXY_HOST="${PROXY_HOST}"
LIGOLO_PROXY_PORT="${PROXY_PORT}"

# Sécurité
LIGOLO_USE_CERTS="${USE_CERTS}"
LIGOLO_IGNORE_CERT="${IGNORE_CERT}"
LIGOLO_CA_CERT="${CERTS_DIR}/ca-cert.pem"

# Comportement
LIGOLO_RETRY="${RETRY}"
LIGOLO_RETRY_DELAY="${RETRY_DELAY}"

# Agent
LIGOLO_VERSION="${LIGOLO_VERSION}"
LIGOLO_BIND_ADDR="0.0.0.0"

# Chemins
LIGOLO_CERTS_DIR="${CERTS_DIR}"
LIGOLO_LOG_FILE="${LOG_FILE}"

# Export
export LIGOLO_PROXY_HOST LIGOLO_PROXY_PORT LIGOLO_USE_CERTS LIGOLO_IGNORE_CERT
export LIGOLO_CA_CERT LIGOLO_RETRY LIGOLO_RETRY_DELAY LIGOLO_CERTS_DIR
EOF
    
    chmod 600 "$CONFIG_FILE"
    log_success "Configuration sauvegardée: ${CONFIG_FILE}"
    
    # Créer le service systemd
    log_info "Création du service systemd..."
    
    AGENT_CMD="/usr/local/bin/ligolo-agent -connect ${PROXY_HOST}:${PROXY_PORT}"
    
    if [ "$IGNORE_CERT" = "true" ]; then
        AGENT_CMD="${AGENT_CMD} -ignore-cert"
    fi
    
    if [ "$RETRY" = "true" ]; then
        AGENT_CMD="${AGENT_CMD} -retry"
    fi
    
    cat > /etc/systemd/system/ligolo-agent.service <<EOF
[Unit]
Description=Ligolo-ng Agent - Network Tunneling
Documentation=https://github.com/nicocha30/ligolo-ng
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${CONFIG_FILE}
ExecStart=${AGENT_CMD}
Restart=always
RestartSec=${RETRY_DELAY}
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=false
PrivateTmp=yes

# Network
BindsTo=network-online.target

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 /etc/systemd/system/ligolo-agent.service
    systemctl daemon-reload
    systemctl enable ligolo-agent
    
    log_success "Service systemd créé et activé"
fi

# =================================================================================================
# ÉTAPE 3 : Information sur les certificats
# =================================================================================================

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 3/3 - Configuration des certificats                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "${USE_CERTS:-false}" = "true" ]; then
    log_warning "Mode certificats activé - Configuration requise"
    echo ""
    echo -e "${YELLOW}Pour utiliser des certificats personnalisés:${NC}"
    echo ""
    echo -e "${CYAN}1. Sur votre machine d'attaque, générez les certificats:${NC}"
    echo -e "   ${GREEN}./generate-ligolo-certs.sh${NC}"
    echo ""
    echo -e "${CYAN}2. Le script génère ces fichiers:${NC}"
    echo -e "   • ca-cert.pem       (Certificat CA à copier sur le Pi)"
    echo -e "   • ca-key.pem        (Clé CA privée - GARDEZ SECRET!)"
    echo -e "   • server-cert.pem   (Pour le proxy)"
    echo -e "   • server-key.pem    (Pour le proxy - SECRET!)"
    echo ""
    echo -e "${CYAN}3. Copiez le certificat CA sur le Raspberry Pi:${NC}"
    echo -e "   ${GREEN}scp ca-cert.pem root@$(hostname -I | awk '{print $1}'):${CERTS_DIR}/${NC}"
    echo ""
    echo -e "${CYAN}4. Ou utilisez le script de déploiement automatique:${NC}"
    echo -e "   ${GREEN}./deploy-agent.sh $(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo -e "${CYAN}5. Vérifiez que le certificat est présent:${NC}"
    echo -e "   ${GREEN}ls -la ${CERTS_DIR}/ca-cert.pem${NC}"
    echo ""
    echo -e "${CYAN}6. Installez le certificat dans le système:${NC}"
    echo -e "   ${GREEN}sudo cp ${CERTS_DIR}/ca-cert.pem /usr/local/share/ca-certificates/ligolo-ca.crt${NC}"
    echo -e "   ${GREEN}sudo update-ca-certificates${NC}"
    echo ""
    echo -e "${CYAN}7. Redémarrez l'agent:${NC}"
    echo -e "   ${GREEN}sudo systemctl restart ligolo-agent${NC}"
    echo ""
    
    log_info "Chemin des certificats: ${CERTS_DIR}"
    log_info "Certificat CA attendu: ${CERTS_DIR}/ca-cert.pem"
    
    # Vérifier si le certificat existe
    if [ -f "${CERTS_DIR}/ca-cert.pem" ]; then
        log_success "Certificat CA trouvé"
        
        # Vérifier la validité
        if openssl x509 -in "${CERTS_DIR}/ca-cert.pem" -noout -checkend 0 2>/dev/null; then
            CERT_EXPIRY=$(openssl x509 -in "${CERTS_DIR}/ca-cert.pem" -noout -enddate | cut -d= -f2)
            log_success "Certificat valide jusqu'au: ${CERT_EXPIRY}"
        else
            log_error "Le certificat a expiré ou est invalide"
        fi
    else
        log_warning "Certificat CA non trouvé - À copier après génération"
    fi
else
    log_info "Mode auto-signé - Certificats non requis"
    echo ""
    echo -e "${CYAN}Sur votre machine d'attaque, démarrez le proxy avec:${NC}"
    echo -e "   ${GREEN}sudo ./proxy -selfcert -laddr 0.0.0.0:${PROXY_PORT:-443}${NC}"
fi

# =================================================================================================
# Création des scripts de gestion
# =================================================================================================

log_info "Création des scripts de gestion..."

# Script de statut
cat > /usr/local/bin/ligolo-status <<'EOF'
#!/bin/bash
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Ligolo-ng Agent - Statut                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
systemctl status ligolo-agent --no-pager | head -10
echo ""
echo "Derniers logs:"
journalctl -u ligolo-agent -n 15 --no-pager
EOF
chmod +x /usr/local/bin/ligolo-status

# Script de configuration
cat > /usr/local/bin/ligolo-config <<EOF
#!/bin/bash
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Pas de configuration trouvée"
    exit 1
fi
source "${CONFIG_FILE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Ligolo-ng - Configuration                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "  Proxy:       \${LIGOLO_PROXY_HOST}:\${LIGOLO_PROXY_PORT}"
echo "  Mode:        \$([ "\${LIGOLO_USE_CERTS}" = "true" ] && echo "Certificats" || echo "Auto-signé")"
echo "  Auto-retry:  \${LIGOLO_RETRY} (délai: \${LIGOLO_RETRY_DELAY}s)"
echo "  Certificats: \${LIGOLO_CERTS_DIR}"
echo "  Config:      ${CONFIG_FILE}"
echo "  Log:         ${LOG_FILE}"
echo ""
if [ "\${LIGOLO_USE_CERTS}" = "true" ]; then
    if [ -f "\${LIGOLO_CA_CERT}" ]; then
        echo "✓ Certificat CA présent"
        openssl x509 -in "\${LIGOLO_CA_CERT}" -noout -subject -dates 2>/dev/null || echo "⚠ Erreur de lecture"
    else
        echo "✗ Certificat CA manquant: \${LIGOLO_CA_CERT}"
    fi
fi
EOF
chmod +x /usr/local/bin/ligolo-config

# Script de logs
cat > /usr/local/bin/ligolo-logs <<'EOF'
#!/bin/bash
echo "Logs en temps réel (Ctrl+C pour quitter):"
journalctl -u ligolo-agent -f
EOF
chmod +x /usr/local/bin/ligolo-logs

# Script de redémarrage
cat > /usr/local/bin/ligolo-restart <<'EOF'
#!/bin/bash
echo "Redémarrage de l'agent..."
systemctl restart ligolo-agent
sleep 2
systemctl status ligolo-agent --no-pager
EOF
chmod +x /usr/local/bin/ligolo-restart

# Script de routes
cat > /usr/local/bin/ligolo-routes <<'EOF'
#!/bin/bash
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Routes réseau actives                                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
ip route show | grep -E "ligolo|tun" --color=never || echo "Aucune route Ligolo"
echo ""
echo "Interfaces TUN:"
ip link show type tun 2>/dev/null | grep -E "^[0-9]+:" || echo "Aucune interface TUN"
EOF
chmod +x /usr/local/bin/ligolo-routes

log_success "Scripts de gestion créés"

# =================================================================================================
# Résumé final
# =================================================================================================

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Installation terminée avec succès!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

log_success "Installation complète"

echo -e "${CYAN}Configuration:${NC}"
echo -e "  Proxy:    ${PROXY_HOST:-Non configuré}:${PROXY_PORT:-N/A}"
echo -e "  Mode:     $([ "${USE_CERTS:-false}" = "true" ] && echo "Certificats" || echo "Auto-signé")"
echo -e "  Config:   ${CONFIG_FILE}"
echo -e "  Certs:    ${CERTS_DIR}"
echo -e "  Log:      ${LOG_FILE}"
echo ""

echo -e "${CYAN}Commandes disponibles:${NC}"
echo -e "  ${GREEN}ligolo-status${NC}   - Afficher le statut"
echo -e "  ${GREEN}ligolo-config${NC}   - Voir la configuration"
echo -e "  ${GREEN}ligolo-logs${NC}     - Suivre les logs"
echo -e "  ${GREEN}ligolo-restart${NC}  - Redémarrer l'agent"
echo -e "  ${GREEN}ligolo-routes${NC}   - Voir les routes"
echo ""

echo -e "${CYAN}Gestion du service:${NC}"
echo -e "  ${GREEN}systemctl start ligolo-agent${NC}    - Démarrer"
echo -e "  ${GREEN}systemctl stop ligolo-agent${NC}     - Arrêter"
echo -e "  ${GREEN}systemctl status ligolo-agent${NC}   - Statut"
echo ""

if [ "${USE_CERTS:-false}" = "true" ]; then
    echo -e "${YELLOW}⚠  Action requise - Certificats:${NC}"
    echo -e "  1. Générer les certificats (machine d'attaque)"
    echo -e "  2. Copier ca-cert.pem vers: ${CERTS_DIR}/"
    echo -e "  3. Installer: ${GREEN}update-ca-certificates${NC}"
    echo -e "  4. Redémarrer: ${GREEN}systemctl restart ligolo-agent${NC}"
    echo ""
fi

echo -e "${CYAN}Sur la machine d'attaque:${NC}"
if [ "${USE_CERTS:-false}" = "true" ]; then
    echo -e "  ${GREEN}sudo ./proxy -certfile server-cert.pem -keyfile server-key.pem -laddr 0.0.0.0:${PROXY_PORT:-443}${NC}"
else
    echo -e "  ${GREEN}sudo ./proxy -selfcert -laddr 0.0.0.0:${PROXY_PORT:-443}${NC}"
fi
echo ""

read -p "Démarrer l'agent maintenant? (y/N): " START_NOW
if [[ ${START_NOW^^} =~ ^Y|YES$ ]]; then
    log_info "Démarrage de l'agent..."
    systemctl start ligolo-agent
    sleep 2
    echo ""
    ligolo-status
fi

echo ""
echo -e "${GREEN}Installation terminée!${NC}"
echo -e "${YELLOW}Consultez les logs: ${GREEN}cat ${LOG_FILE}${NC}"
echo ""

log_success "Script terminé"