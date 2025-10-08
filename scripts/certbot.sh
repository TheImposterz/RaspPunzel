#!/bin/bash

# =================================================================================================
# Ligolo-ng Certificate Generator
# =================================================================================================
# Génère une CA et des certificats pour Ligolo-ng avec logs détaillés
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
CERTS_DIR="${1:-./ligolo-certs}"
LOG_FILE="${CERTS_DIR}/cert-generation.log"
CA_DAYS=3650
SERVER_DAYS=365
KEY_SIZE=4096

# =================================================================================================
# Fonctions de logging
# =================================================================================================

log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
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
# En-tête
# =================================================================================================

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Ligolo-ng - Générateur de Certificats${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Créer le dossier
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"
touch "$LOG_FILE"

log_info "Début de la génération des certificats"
log_info "Répertoire: $(pwd)"
log_info "Log: ${LOG_FILE}"

echo -e "${CYAN}Répertoire de sortie: ${CERTS_DIR}${NC}"
echo -e "${CYAN}Fichier de log: ${LOG_FILE}${NC}"
echo ""

# =================================================================================================
# ÉTAPE 1 : Autorité de Certification (CA)
# =================================================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 1/5 - Autorité de Certification (CA)                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -f "ca-cert.pem" ] && [ -f "ca-key.pem" ]; then
    log_warning "CA existante détectée"
    
    EXPIRY=$(openssl x509 -in ca-cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)
    echo -e "${YELLOW}CA existante:${NC}"
    echo -e "  Expire le: ${EXPIRY}"
    echo ""
    read -p "Recréer la CA? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "CA existante conservée"
        CA_EXISTS=true
    else
        log_info "Recréation de la CA"
        CA_EXISTS=false
    fi
else
    CA_EXISTS=false
fi

if [ "$CA_EXISTS" = false ]; then
    log_info "Configuration de la CA"
    
    read -p "Pays (C) [FR]: " CA_COUNTRY
    CA_COUNTRY=${CA_COUNTRY:-FR}
    
    read -p "État/Province (ST) [Ile-de-France]: " CA_STATE
    CA_STATE=${CA_STATE:-Ile-de-France}
    
    read -p "Ville (L) [Paris]: " CA_CITY
    CA_CITY=${CA_CITY:-Paris}
    
    read -p "Organisation (O) [RaspPunzel]: " CA_ORG
    CA_ORG=${CA_ORG:-RaspPunzel}
    
    read -p "Unité (OU) [Security]: " CA_OU
    CA_OU=${CA_OU:-Security}
    
    read -p "Nom commun (CN) [Ligolo-CA]: " CA_CN
    CA_CN=${CA_CN:-Ligolo-CA}
    
    log_info "Paramètres CA: C=${CA_COUNTRY}, ST=${CA_STATE}, L=${CA_CITY}, O=${CA_ORG}, OU=${CA_OU}, CN=${CA_CN}"
    
    echo ""
    log_info "Génération de la clé privée CA (${KEY_SIZE} bits)..."
    
    if openssl genrsa -out ca-key.pem $KEY_SIZE 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        log_success "Clé CA générée"
    else
        log_error "Échec de génération de la clé CA"
        exit 1
    fi
    
    log_info "Création du certificat CA (valide ${CA_DAYS} jours)..."
    
    if openssl req -new -x509 -days $CA_DAYS -key ca-key.pem -out ca-cert.pem \
        -subj "/C=$CA_COUNTRY/ST=$CA_STATE/L=$CA_CITY/O=$CA_ORG/OU=$CA_OU/CN=$CA_CN" \
        2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        log_success "Certificat CA créé"
    else
        log_error "Échec de création du certificat CA"
        exit 1
    fi
    
    chmod 600 ca-key.pem
    chmod 644 ca-cert.pem
    
    log_success "CA créée avec succès"
    log_info "Certificat: ca-cert.pem"
    log_info "Clé privée: ca-key.pem (CONFIDENTIEL)"
fi

echo ""

# =================================================================================================
# ÉTAPE 2 : Certificat Serveur (Proxy)
# =================================================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 2/5 - Certificat Serveur (Proxy)                     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

log_info "Configuration du certificat serveur"

while true; do
    read -p "IP publique du serveur proxy: " SERVER_IP
    if [ -n "$SERVER_IP" ]; then
        log_info "IP serveur: ${SERVER_IP}"
        break
    fi
    log_error "L'IP du serveur est requise"
done

read -p "Nom de domaine (optionnel): " SERVER_DOMAIN
if [ -n "$SERVER_DOMAIN" ]; then
    log_info "Domaine: ${SERVER_DOMAIN}"
fi

read -p "Nom commun (CN) [ligolo-proxy]: " SERVER_CN
SERVER_CN=${SERVER_CN:-ligolo-proxy}
log_info "CN serveur: ${SERVER_CN}"

echo ""
log_info "Génération de la clé privée serveur (${KEY_SIZE} bits)..."

if openssl genrsa -out server-key.pem $KEY_SIZE 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
    log_success "Clé serveur générée"
else
    log_error "Échec de génération de la clé serveur"
    exit 1
fi

log_info "Création de la demande de signature (CSR)..."

if openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=${CA_COUNTRY:-FR}/ST=${CA_STATE:-Ile-de-France}/L=${CA_CITY:-Paris}/O=${CA_ORG:-RaspPunzel}/CN=$SERVER_CN" \
    2>&1 | tee -a "$LOG_FILE" >/dev/null; then
    log_success "CSR créée"
else
    log_error "Échec de création du CSR"
    exit 1
fi

log_info "Configuration des extensions (SAN)..."

cat > server-ext.cnf <<EOF
subjectAltName = IP:$SERVER_IP
EOF

if [ -n "$SERVER_DOMAIN" ]; then
    echo "subjectAltName = IP:$SERVER_IP,DNS:$SERVER_DOMAIN" > server-ext.cnf
    log_info "SAN: IP:${SERVER_IP}, DNS:${SERVER_DOMAIN}"
else
    log_info "SAN: IP:${SERVER_IP}"
fi

cat >> server-ext.cnf <<EOF
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOF

log_info "Signature du certificat serveur avec la CA..."

if openssl x509 -req -days $SERVER_DAYS -in server.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -out server-cert.pem -extfile server-ext.cnf \
    2>&1 | tee -a "$LOG_FILE" >/dev/null; then
    log_success "Certificat serveur signé"
else
    log_error "Échec de signature du certificat serveur"
    exit 1
fi

rm -f server.csr server-ext.cnf

chmod 600 server-key.pem
chmod 644 server-cert.pem

log_success "Certificat serveur créé avec succès"
log_info "Certificat: server-cert.pem"
log_info "Clé privée: server-key.pem (CONFIDENTIEL)"

echo ""

# =================================================================================================
# ÉTAPE 3 : Vérification des certificats
# =================================================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 3/5 - Vérification des certificats                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

log_info "Vérification du certificat CA..."
openssl x509 -in ca-cert.pem -noout -text | grep -E "Subject:|Issuer:|Not" | tee -a "$LOG_FILE"

echo ""
log_info "Vérification du certificat serveur..."
openssl x509 -in server-cert.pem -noout -text | grep -E "Subject:|Issuer:|Not|DNS:|IP Address:" | tee -a "$LOG_FILE"

echo ""
log_info "Vérification de la chaîne de confiance..."

if openssl verify -CAfile ca-cert.pem server-cert.pem 2>&1 | tee -a "$LOG_FILE"; then
    log_success "Chaîne de confiance valide"
else
    log_error "Erreur de vérification"
    exit 1
fi

echo ""

# =================================================================================================
# ÉTAPE 4 : Scripts de déploiement
# =================================================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 4/5 - Génération des scripts                         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

log_info "Création des scripts de déploiement..."

# Script pour démarrer le proxy
cat > start-proxy.sh <<EOF
#!/bin/bash
# Démarrer le proxy Ligolo-ng avec certificats

PROXY_PORT=443
BIND_ADDR="0.0.0.0"

echo "[+] Création de l'interface TUN..."
sudo ip tuntap add user \$(whoami) mode tun ligolo 2>/dev/null || echo "[!] Interface existe déjà"
sudo ip link set ligolo up

echo "[+] Démarrage du proxy sur \${BIND_ADDR}:\${PROXY_PORT}..."
sudo ./proxy \\
    -certfile $(pwd)/server-cert.pem \\
    -keyfile $(pwd)/server-key.pem \\
    -laddr \${BIND_ADDR}:\${PROXY_PORT}
EOF

chmod +x start-proxy.sh
log_success "Script créé: start-proxy.sh"

# Script de déploiement sur l'agent
cat > deploy-to-agent.sh <<'EOF'
#!/bin/bash
# Déployer les certificats sur l'agent RaspPunzel

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

AGENT_IP="$1"
AGENT_USER="${2:-root}"
CERTS_DIR="/etc/rasppunzel/certs"

if [ -z "$AGENT_IP" ]; then
    echo -e "${RED}Usage: $0 <agent-ip> [user]${NC}"
    echo "Exemple: $0 192.168.1.100"
    echo "         $0 192.168.1.100 kali"
    exit 1
fi

echo -e "${GREEN}[+] Déploiement sur ${AGENT_USER}@${AGENT_IP}${NC}"
echo ""

# Vérifier la connexion SSH
echo -e "${YELLOW}[~] Test de connexion SSH...${NC}"
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ${AGENT_USER}@${AGENT_IP} "echo ok" &>/dev/null; then
    echo -e "${RED}[!] Impossible de se connecter via SSH${NC}"
    echo -e "${YELLOW}[~] Vérifiez:${NC}"
    echo "  - L'IP de l'agent est correcte"
    echo "  - Le service SSH est actif"
    echo "  - Votre clé SSH est autorisée"
    exit 1
fi
echo -e "${GREEN}[+] Connexion SSH OK${NC}"
echo ""

# Copier le certificat CA
echo -e "${YELLOW}[~] Copie du certificat CA...${NC}"
EOF

echo "if ! scp ca-cert.pem ${AGENT_USER}@\${AGENT_IP}:/tmp/ 2>&1 | tee -a deploy.log; then" >> deploy-to-agent.sh

cat >> deploy-to-agent.sh <<'EOF'
    echo -e "${RED}[!] Échec de la copie${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Certificat copié${NC}"
echo ""

# Installer sur l'agent
echo -e "${YELLOW}[~] Installation sur l'agent...${NC}"
ssh ${AGENT_USER}@${AGENT_IP} "
    set -e
    
    # Créer le répertoire
    sudo mkdir -p ${CERTS_DIR}
    
    # Déplacer le certificat
    sudo mv /tmp/ca-cert.pem ${CERTS_DIR}/
    sudo chmod 644 ${CERTS_DIR}/ca-cert.pem
    
    echo '[+] Certificat installé: ${CERTS_DIR}/ca-cert.pem'
    
    # Installer dans le système
    sudo cp ${CERTS_DIR}/ca-cert.pem /usr/local/share/ca-certificates/ligolo-ca.crt
    sudo update-ca-certificates
    
    echo '[+] Certificat ajouté au système'
    
    # Mettre à jour la configuration
    if [ -f /etc/rasppunzel/ligolo.conf ]; then
        sudo sed -i 's/LIGOLO_IGNORE_CERT=.*/LIGOLO_IGNORE_CERT=\"false\"/' /etc/rasppunzel/ligolo.conf
        sudo sed -i 's/LIGOLO_USE_CERTS=.*/LIGOLO_USE_CERTS=\"true\"/' /etc/rasppunzel/ligolo.conf
        echo '[+] Configuration mise à jour'
    fi
    
    # Vérifier le certificat
    if openssl x509 -in ${CERTS_DIR}/ca-cert.pem -noout -subject; then
        echo '[+] Certificat valide'
    else
        echo '[!] Erreur de validation'
        exit 1
    fi
"

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Déploiement réussi!                                        ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Prochaines étapes:${NC}"
    echo -e "  1. Redémarrer l'agent: ${GREEN}ssh ${AGENT_USER}@${AGENT_IP} 'sudo systemctl restart ligolo-agent'${NC}"
    echo -e "  2. Vérifier les logs:  ${GREEN}ssh ${AGENT_USER}@${AGENT_IP} 'sudo journalctl -u ligolo-agent -f'${NC}"
    echo ""
else
    echo -e "${RED}[!] Erreur lors du déploiement${NC}"
    exit 1
fi
EOF

chmod +x deploy-to-agent.sh
log_success "Script créé: deploy-to-agent.sh"

# Instructions complètes
cat > INSTRUCTIONS.md <<EOF
# Instructions d'utilisation - Ligolo-ng avec certificats

## 📁 Fichiers générés

### Certificats
- \`ca-cert.pem\` - Certificat de l'Autorité de Certification (Public)
- \`ca-key.pem\` - Clé privée de la CA (**CONFIDENTIEL**)
- \`server-cert.pem\` - Certificat du serveur proxy (Public)
- \`server-key.pem\` - Clé privée du serveur (**CONFIDENTIEL**)

### Scripts
- \`start-proxy.sh\` - Démarrer le proxy sur la machine d'attaque
- \`deploy-to-agent.sh\` - Déployer automatiquement sur le Raspberry Pi
- \`cert-generation.log\` - Log détaillé de la génération

---

## 🖥️ Configuration du serveur (Machine d'attaque)

### 1. Créer l'interface TUN
\`\`\`bash
sudo ip tuntap add user \$(whoami) mode tun ligolo
sudo ip link set ligolo up
\`\`\`

### 2. Démarrer le proxy
\`\`\`bash
./start-proxy.sh
\`\`\`

Ou manuellement:
\`\`\`bash
sudo ./proxy \\
    -certfile $(pwd)/server-cert.pem \\
    -keyfile $(pwd)/server-key.pem \\
    -laddr 0.0.0.0:443
\`\`\`

### 3. Vérifier l'écoute
\`\`\`bash
sudo netstat -tulpn | grep 443
\`\`\`

---

## 🍓 Configuration du Raspberry Pi (Agent)

### Option A: Déploiement automatique (Recommandé)

\`\`\`bash
./deploy-to-agent.sh <IP-DU-RASPBERRY>
\`\`\`

Exemple:
\`\`\`bash
./deploy-to-agent.sh 192.168.1.100
# ou avec un utilisateur spécifique
./deploy-to-agent.sh 192.168.1.100 kali
\`\`\`

Le script va:
1. ✓ Tester la connexion SSH
2. ✓ Copier ca-cert.pem sur le Pi
3. ✓ Installer le certificat dans \`/etc/rasppunzel/certs/\`
4. ✓ Ajouter le certificat au système
5. ✓ Mettre à jour la configuration Ligolo

### Option B: Déploiement manuel

#### 1. Copier le certificat
\`\`\`bash
scp ca-cert.pem root@<IP-RASPBERRY>:/tmp/
\`\`\`

#### 2. Sur le Raspberry Pi
\`\`\`bash
# Se connecter
ssh root@<IP-RASPBERRY>

# Installer le certificat
sudo mkdir -p /etc/rasppunzel/certs
sudo mv /tmp/ca-cert.pem /etc/rasppunzel/certs/
sudo chmod 644 /etc/rasppunzel/certs/ca-cert.pem

# Ajouter au système
sudo cp /etc/rasppunzel/certs/ca-cert.pem /usr/local/share/ca-certificates/ligolo-ca.crt
sudo update-ca-certificates

# Vérifier
ls -la /etc/rasppunzel/certs/ca-cert.pem
\`\`\`

#### 3. Mettre à jour la configuration
\`\`\`bash
sudo nano /etc/rasppunzel/ligolo.conf
\`\`\`

Modifier:
\`\`\`
LIGOLO_USE_CERTS="true"
LIGOLO_IGNORE_CERT="false"
\`\`\`

### 4. Redémarrer l'agent
\`\`\`bash
sudo systemctl restart ligolo-agent
\`\`\`

### 5. Vérifier les logs
\`\`\`bash
sudo journalctl -u ligolo-agent -f
\`\`\`

Rechercher:
- ✓ "connected" - Connexion établie
- ✓ "session created" - Session créée
- ✗ "certificate" errors - Erreurs de certificat

---

## 🔍 Vérification

### Sur le serveur
\`\`\`bash
# Vérifier l'écoute
sudo netstat -tulpn | grep 443

# Test du certificat
echo | openssl s_client -connect ${SERVER_IP}:443 -CAfile ca-cert.pem
\`\`\`

### Sur le Raspberry Pi
\`\`\`bash
# Statut de l'agent
ligolo-status

# Configuration
ligolo-config

# Logs en direct
ligolo-logs

# Test de connexion
telnet ${SERVER_IP} 443
\`\`\`

---

## 🌐 Utilisation du tunnel

### 1. Sur le proxy, lister les sessions
\`\`\`
ligolo-ng » session
\`\`\`

### 2. Sélectionner la session
\`\`\`
ligolo-ng » session 1
\`\`\`

### 3. Lister les interfaces réseau
\`\`\`
[Agent] » ifconfig
\`\`\`

### 4. Démarrer le tunnel
\`\`\`
[Agent] » start
\`\`\`

### 5. Ajouter les routes (sur votre machine)
\`\`\`bash
# Réseau cible (exemple)
sudo ip route add 192.168.1.0/24 dev ligolo
sudo ip route add 10.0.0.0/24 dev ligolo

# Vérifier
ip route show
\`\`\`

### 6. Tester
\`\`\`bash
# Ping une machine du réseau cible
ping 192.168.1.50

# Scanner un réseau
nmap 192.168.1.0/24
\`\`\`

---

## 🔐 Sécurité

### ⚠️ IMPORTANT

**Fichiers confidentiels** - Ne JAMAIS les partager:
- \`ca-key.pem\` - Clé privée de la CA
- \`server-key.pem\` - Clé privée du serveur

**Permissions recommandées:**
\`\`\`bash
chmod 600 ca-key.pem server-key.pem
chmod 644 ca-cert.pem server-cert.pem
\`\`\`

**Ne pas committer dans Git:**
Le fichier \`.gitignore\` a été créé automatiquement.

### 📦 Sauvegarde

Sauvegardez ces fichiers en lieu sûr:
- \`ca-key.pem\` (nécessaire pour signer de nouveaux certificats)
- \`server-key.pem\` et \`server-cert.pem\`

### 📅 Renouvellement

- **CA**: Valide ${CA_DAYS} jours (~10 ans)
- **Serveur**: Valide ${SERVER_DAYS} jours (1 an)

Pour renouveler le certificat serveur:
\`\`\`bash
./generate-ligolo-certs.sh $(pwd)
\`\`\`

---

## 🐛 Dépannage

### L'agent ne se connecte pas

1. Vérifier que le proxy est démarré:
   \`\`\`bash
   sudo netstat -tulpn | grep 443
   \`\`\`

2. Vérifier la connexion réseau:
   \`\`\`bash
   # Sur le Pi
   ping ${SERVER_IP}
   telnet ${SERVER_IP} 443
   \`\`\`

3. Vérifier les logs:
   \`\`\`bash
   sudo journalctl -u ligolo-agent -n 50
   \`\`\`

### Erreurs de certificat

1. Vérifier que le certificat est installé:
   \`\`\`bash
   ls -la /etc/rasppunzel/certs/ca-cert.pem
   \`\`\`

2. Vérifier la validité:
   \`\`\`bash
   openssl x509 -in /etc/rasppunzel/certs/ca-cert.pem -noout -dates
   \`\`\`

3. Réinstaller:
   \`\`\`bash
   sudo update-ca-certificates --fresh
   \`\`\`

### Firewall bloque la connexion

\`\`\`bash
# Sur le serveur
sudo ufw allow 443/tcp

# Ou iptables
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
\`\`\`

---

## 📚 Ressources

- **Ligolo-ng**: https://github.com/nicocha30/ligolo-ng
- **RaspPunzel**: https://github.com/TheImposterz/RaspPunzel
- **Documentation**: \`cat cert-generation.log\`

---

## 📞 Support

En cas de problème:

1. Consultez les logs:
   - Génération: \`cat cert-generation.log\`
   - Installation: \`cat /etc/rasppunzel/ligolo-install.log\`
   - Agent: \`sudo journalctl -u ligolo-agent -n 100\`

2. Vérifiez la configuration:
   \`\`\`bash
   ligolo-config
   \`\`\`

3. Testez la connectivité:
   \`\`\`bash
   telnet ${SERVER_IP} 443
   \`\`\`

---

Généré le: $(date)
Serveur: ${SERVER_IP}:443
$([ -n "$SERVER_DOMAIN" ] && echo "Domaine: ${SERVER_DOMAIN}")
EOF

log_success "Documentation créée: INSTRUCTIONS.md"

# Créer .gitignore
cat > .gitignore <<'EOF'
# Ne JAMAIS committer les clés privées!
*.pem
*.key
*.csr
*.srl
ca-key.pem
server-key.pem

# Logs
*.log
EOF

log_success "Fichier .gitignore créé"

echo ""

# =================================================================================================
# ÉTAPE 5 : Résumé et prochaines étapes
# =================================================================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ÉTAPE 5/5 - Résumé                                         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

log_success "Génération des certificats terminée"

# Résumé visuel
echo -e "${GREEN}✓ Certificats générés avec succès!${NC}"
echo ""
echo -e "${CYAN}📁 Répertoire: ${CERTS_DIR}${NC}"
echo ""
echo -e "${YELLOW}Certificats créés:${NC}"
echo -e "  ${GREEN}✓${NC} ca-cert.pem           (CA publique - 📤 À partager)"
echo -e "  ${RED}✓${NC} ca-key.pem            (CA privée - 🔒 CONFIDENTIEL)"
echo -e "  ${GREEN}✓${NC} server-cert.pem       (Serveur - 📤 Public)"
echo -e "  ${RED}✓${NC} server-key.pem        (Serveur - 🔒 CONFIDENTIEL)"
echo ""
echo -e "${YELLOW}Scripts générés:${NC}"
echo -e "  ${GREEN}✓${NC} start-proxy.sh        (Démarrer le proxy)"
echo -e "  ${GREEN}✓${NC} deploy-to-agent.sh    (Déployer sur le Pi)"
echo -e "  ${GREEN}✓${NC} INSTRUCTIONS.md       (Documentation complète)"
echo -e "  ${GREEN}✓${NC} cert-generation.log   (Log détaillé)"
echo ""

# Informations sur les certificats
echo -e "${CYAN}📋 Informations des certificats:${NC}"
echo ""
echo -e "${YELLOW}CA:${NC}"
openssl x509 -in ca-cert.pem -noout -subject -dates 2>/dev/null | sed 's/^/  /'
echo ""
echo -e "${YELLOW}Serveur:${NC}"
openssl x509 -in server-cert.pem -noout -subject -dates 2>/dev/null | sed 's/^/  /'
echo ""

# Prochaines étapes
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🚀 Prochaines étapes${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}1️⃣  Sur cette machine (Serveur d'attaque):${NC}"
echo ""
echo -e "   ${GREEN}./start-proxy.sh${NC}"
echo -e "   ou"
echo -e "   ${GREEN}sudo ./proxy -certfile server-cert.pem -keyfile server-key.pem -laddr 0.0.0.0:443${NC}"
echo ""

echo -e "${CYAN}2️⃣  Déployer sur le Raspberry Pi:${NC}"
echo ""
echo -e "   ${GREEN}./deploy-to-agent.sh <IP-DU-RASPBERRY>${NC}"
echo ""
echo -e "   Exemple: ${GREEN}./deploy-to-agent.sh 192.168.1.100${NC}"
echo ""

echo -e "${CYAN}3️⃣  Vérifier la connexion:${NC}"
echo ""
echo -e "   Sur le Pi: ${GREEN}ligolo-status${NC}"
echo ""

echo -e "${CYAN}4️⃣  Documentation complète:${NC}"
echo ""
echo -e "   ${GREEN}cat INSTRUCTIONS.md${NC}"
echo ""

# Warnings de sécurité
echo -e "${RED}⚠️  SÉCURITÉ CRITIQUE ⚠️${NC}"
echo ""
echo -e "${YELLOW}Protégez ces fichiers:${NC}"
echo -e "  ${RED}🔒 ca-key.pem${NC} - Ne JAMAIS partager!"
echo -e "  ${RED}🔒 server-key.pem${NC} - Ne JAMAIS partager!"
echo ""
echo -e "${YELLOW}Commandes recommandées:${NC}"
echo -e "  ${GREEN}chmod 600 ca-key.pem server-key.pem${NC}"
echo -e "  ${GREEN}chmod 644 ca-cert.pem server-cert.pem${NC}"
echo ""

# Log final
log_success "Script terminé avec succès"
log_info "Tous les détails dans: ${LOG_FILE}"

echo -e "${GREEN}✅ Terminé!${NC}"
echo -e "${CYAN}📄 Consultez les logs: ${GREEN}cat ${LOG_FILE}${NC}"
echo ""