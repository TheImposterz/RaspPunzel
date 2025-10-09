#!/bin/bash

# =================================================================================================
# RaspPunzel - Web Dashboard Installation Script
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# =================================================================================================
# Configuration
# =================================================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load configuration
if [[ -f "${PROJECT_ROOT}/config.sh" ]]; then
    source "${PROJECT_ROOT}/config.sh"
else
    echo -e "${RED}Error: config.sh not found${NC}"
    exit 1
fi

# Check if web dashboard is enabled
if [[ "${ENABLE_WEB_DASHBOARD}" != "true" ]]; then
    echo -e "${YELLOW}[~] Web dashboard disabled in config${NC}"
    exit 0
fi

# =================================================================================================
# Validation de la structure du repository
# =================================================================================================

echo -e "${YELLOW}[~] Validating repository structure...${NC}"

REQUIRED_FILES=(
    "config/services/nginx-rasppunzel.conf"
    "config/services/rasppunzel-web.service"
    "web/api/app.py"
    "web/api/requirements.txt"
    "web/index.html"
    "web/dashboard.html"
)

MISSING_FILES=0
for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "${PROJECT_ROOT}/${file}" ]]; then
        echo -e "${RED}[!] Missing required file: ${file}${NC}"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

if [[ $MISSING_FILES -gt 0 ]]; then
    echo -e "${RED}[!] Repository structure incomplete (${MISSING_FILES} files missing)${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Repository structure validated${NC}"

# =================================================================================================
# Installation des dépendances système
# =================================================================================================

echo -e "${YELLOW}[~] Installing system packages...${NC}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nginx lsof > /dev/null

echo -e "${GREEN}[+] System packages installed${NC}"

# =================================================================================================
# Création de la structure de répertoires
# =================================================================================================

echo -e "${YELLOW}[~] Creating directory structure...${NC}"

mkdir -p /opt/rasppunzel/web/api
mkdir -p /opt/rasppunzel/web/static
mkdir -p /opt/rasppunzel/config
mkdir -p /var/log/rasppunzel

echo -e "${GREEN}[+] Directory structure created${NC}"

# =================================================================================================
# Copie des fichiers web depuis le repository
# =================================================================================================

echo -e "${YELLOW}[~] Copying web files...${NC}"

# Copier tous les fichiers web
cp -r "${PROJECT_ROOT}/web/"* /opt/rasppunzel/web/

# Rendre app.py exécutable
chmod +x /opt/rasppunzel/web/api/app.py

# Vérifier que les fichiers essentiels sont bien là
if [[ ! -f /opt/rasppunzel/web/api/app.py ]]; then
    echo -e "${RED}[!] Error: app.py not copied properly${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Web files copied${NC}"

# =================================================================================================
# Installation de l'environnement Python
# =================================================================================================

echo -e "${YELLOW}[~] Setting up Python virtual environment...${NC}"

cd /opt/rasppunzel/web/api

# Créer venv
python3 -m venv venv

# Activer et installer les dépendances
source venv/bin/activate
pip3 install --quiet --upgrade pip
pip3 install --quiet -r requirements.txt
deactivate

echo -e "${GREEN}[+] Python environment ready${NC}"

# =================================================================================================
# Configuration Nginx
# =================================================================================================

echo -e "${YELLOW}[~] Configuring Nginx...${NC}"

# Copier la configuration
cp "${PROJECT_ROOT}/config/services/nginx-rasppunzel.conf" /etc/nginx/sites-available/rasppunzel

# Activer le site
ln -sf /etc/nginx/sites-available/rasppunzel /etc/nginx/sites-enabled/rasppunzel

# Désactiver le site par défaut
rm -f /etc/nginx/sites-enabled/default

# Tester la configuration
if ! nginx -t 2>&1 | grep -q "successful"; then
    echo -e "${RED}[!] Nginx configuration test failed${NC}"
    nginx -t
    exit 1
fi

echo -e "${GREEN}[+] Nginx configured${NC}"

# =================================================================================================
# Installation du service systemd
# =================================================================================================

echo -e "${YELLOW}[~] Installing systemd service...${NC}"

# Copier le service
cp "${PROJECT_ROOT}/config/services/rasppunzel-web.service" \
   /etc/systemd/system/rasppunzel-web.service

# Recharger systemd
systemctl daemon-reload

# Activer les services
systemctl enable rasppunzel-web
systemctl enable nginx

echo -e "${GREEN}[+] Service installed and enabled${NC}"

# =================================================================================================
# Configuration de l'authentification
# =================================================================================================

echo -e "${YELLOW}[~] Setting up authentication...${NC}"

# Créer le fichier de credentials
cat > /opt/rasppunzel/web/.credentials <<EOF
RaspPunzel Web Dashboard Credentials
====================================
URL: http://$(hostname -I | awk '{print $1}'):8080
Username: admin
Password: rasppunzel

IMPORTANT: Change password after first login via web interface
====================================
EOF

chmod 600 /opt/rasppunzel/web/.credentials

# Créer le répertoire de config si nécessaire
mkdir -p /opt/rasppunzel/config

echo -e "${GREEN}[+] Authentication configured${NC}"

# =================================================================================================
# Démarrage des services
# =================================================================================================

echo -e "${YELLOW}[~] Starting services...${NC}"

# Redémarrer les services
systemctl restart rasppunzel-web
systemctl restart nginx

# Attendre un peu que les services démarrent
sleep 2

# Vérifier le statut
SERVICES_OK=true

if systemctl is-active --quiet rasppunzel-web; then
    echo -e "${GREEN}[+] rasppunzel-web: running${NC}"
else
    echo -e "${RED}[!] rasppunzel-web: failed${NC}"
    SERVICES_OK=false
fi

if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}[+] nginx: running${NC}"
else
    echo -e "${RED}[!] nginx: failed${NC}"
    SERVICES_OK=false
fi

# =================================================================================================
# Résumé de l'installation
# =================================================================================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Web Dashboard Installation Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  ${YELLOW}URL:${NC} http://$(hostname -I | awk '{print $1}'):8080"
echo -e "  ${YELLOW}Credentials:${NC} cat /opt/rasppunzel/web/.credentials"
echo ""
echo -e "  ${YELLOW}Services:${NC}"
echo -e "    - Flask API: systemctl status rasppunzel-web"
echo -e "    - Nginx:     systemctl status nginx"
echo ""
echo -e "  ${YELLOW}Logs:${NC}"
echo -e "    - API:   journalctl -u rasppunzel-web -f"
echo -e "    - Nginx: tail -f /var/log/nginx/rasppunzel-*.log"
echo ""

if [[ "$SERVICES_OK" != "true" ]]; then
    echo -e "${YELLOW}[!] Some services failed to start. Check logs above.${NC}"
    echo ""
    exit 1
fi

exit 0