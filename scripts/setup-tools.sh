#!/bin/bash

# =============================================================================
# RaspPunzel - Installation des Outils de Pentest
# Version intégrée avec Dashboard Web
# Basé sur Pi-PwnBox-RogueAP avec améliorations
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
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_TOOLS_INTEGRATED=false

# Détecter si le dashboard web est installé
detect_web_dashboard() {
    if [ -f "$PROJECT_ROOT/web/api/app.py" ] && [ -f "$PROJECT_ROOT/web/dashboard.html" ]; then
        print_status "Dashboard web détecté - Intégration des outils activée"
        WEB_TOOLS_INTEGRATED=true
    else
        print_status "Dashboard web non détecté - Installation classique"
    fi
}

# Installation des outils système de base
install_system_tools() {
    print_status "Installation des outils système de base..."
    
    apt-get update -qq
    
    # Outils système essentiels
    apt-get install -y -qq \
        curl wget git nmap vim nano htop iotop \
        build-essential pkg-config cmake \
        python3-pip python3-venv python3-dev \
        nodejs npm \
        nginx \
        openssh-server \
        screen tmux \
        zip unzip \
        net-tools \
        tcpdump wireshark-common \
        nmap masscan \
        john hashcat \
        sqlmap \
        nikto \
        dirb gobuster \
        hydra medusa \
        binwalk foremost \
        steghide stegosuite
    
    print_success "Outils système installés"
}

# Installation des outils WiFi
install_wifi_tools() {
    print_status "Installation des outils WiFi..."
    
    apt-get install -y -qq \
        aircrack-ng \
        reaver bully \
        pixiewps \
        hostapd hostapd-wpe \
        dnsmasq \
        kismet \
        wifite \
        hcxdumptool hcxtools \
        cowpatty \
        mdk4 mdk3 \
        ettercap-text-only \
        bettercap \
        macchanger \
        wireless-tools wpasupplicant
    
    print_success "Outils WiFi installés"
}

# Installation des frameworks de pentest
install_frameworks() {
    print_status "Installation des frameworks de pentest..."
    
    # Metasploit (si pas déjà installé)
    if ! command -v msfconsole &> /dev/null; then
        apt-get install -y -qq metasploit-framework
    fi
    
    # Installation manuelle de frameworks populaires
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR"
    
    # Empire
    if [ ! -d "Empire" ]; then
        print_status "Installation d'Empire..."
        git clone --recursive https://github.com/EmpireProject/Empire.git
        cd Empire
        ./setup/install.sh -qq 2>/dev/null || true
        cd ..
    fi
    
    # Social Engineer Toolkit
    if [ ! -d "social-engineer-toolkit" ]; then
        print_status "Installation du Social Engineer Toolkit..."
        git clone https://github.com/trustedsec/social-engineer-toolkit/ social-engineer-toolkit
        cd social-engineer-toolkit
        python3 setup.py install 2>/dev/null || true
        cd ..
    fi
    
    # BeEF
    if [ ! -d "beef" ]; then
        print_status "Installation de BeEF..."
        git clone https://github.com/beefproject/beef.git
        cd beef
        ./install 2>/dev/null || true
        cd ..
    fi
    
    print_success "Frameworks installés"
}

# Installation d'outils WiFi avancés
install_advanced_wifi_tools() {
    print_status "Installation d'outils WiFi avancés..."
    
    cd "$TOOLS_DIR"
    
    # Wifipumpkin3
    if [ ! -d "wifipumpkin3" ]; then
        print_status "Installation de Wifipumpkin3..."
        git clone https://github.com/P0cL4bs/wifipumpkin3.git
        cd wifipumpkin3
        pip3 install -r requirements.txt 2>/dev/null || true
        python3 setup.py install 2>/dev/null || true
        cd ..
    fi
    
    # Wifiphisher
    if [ ! -d "wifiphisher" ]; then
        print_status "Installation de Wifiphisher..."
        git clone https://github.com/wifiphisher/wifiphisher.git
        cd wifiphisher
        pip3 install -r requirements.txt 2>/dev/null || true
        python3 setup.py install 2>/dev/null || true
        cd ..
    fi
    
    # Fluxion
    if [ ! -d "fluxion" ]; then
        print_status "Installation de Fluxion..."
        git clone https://github.com/FluxionNetwork/fluxion.git
        chmod +x fluxion/fluxion
    fi
    
    # EAPHammer
    if [ ! -d "eaphammer" ]; then
        print_status "Installation d'EAPHammer..."
        git clone https://github.com/s0lst1c3/eaphammer.git
        cd eaphammer
        # Installation des dépendances sans interaction
        yes | ./kali-setup 2>/dev/null || true
        cd ..
    fi
    
    # Airgeddon
    if [ ! -d "airgeddon" ]; then
        print_status "Installation d'Airgeddon..."
        git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
        chmod +x airgeddon/airgeddon.sh
    fi
    
    # Berate_ap
    if [ ! -d "berate_ap" ]; then
        print_status "Installation de Berate_ap..."
        git clone https://github.com/sensepost/berate_ap.git
    fi
    
    # WPA_Sycophant
    if [ ! -d "wpa_sycophant" ]; then
        print_status "Installation de WPA_Sycophant..."
        git clone https://github.com/sensepost/wpa_sycophant.git
    fi
    
    print_success "Outils WiFi avancés installés"
}

# Installation d'outils de reconnaissance
install_recon_tools() {
    print_status "Installation d'outils de reconnaissance..."
    
    cd "$TOOLS_DIR"
    
    # TheHarvester
    if [ ! -d "theHarvester" ]; then
        git clone https://github.com/laramies/theHarvester.git
        cd theHarvester
        pip3 install -r requirements/base.txt 2>/dev/null || true
        cd ..
    fi
    
    # Sublist3r
    if [ ! -d "Sublist3r" ]; then
        git clone https://github.com/aboul3la/Sublist3r.git
        cd Sublist3r
        pip3 install -r requirements.txt 2>/dev/null || true
        cd ..
    fi
    
    # Recon-ng
    if [ ! -d "recon-ng" ]; then
        git clone https://github.com/lanmaster53/recon-ng.git
        cd recon-ng
        pip3 install -r REQUIREMENTS 2>/dev/null || true
        cd ..
    fi
    
    
    
    # Enum4linux
    if [ ! -d "enum4linux-ng" ]; then
        git clone https://github.com/cddmp/enum4linux-ng.git
        cd enum4linux-ng
        pip3 install -r requirements.txt 2>/dev/null || true
        cd ..
    fi
    
    print_success "Outils de reconnaissance installés"
}

# Installation d'outils d'exploitation web
install_web_tools() {
    print_status "Installation d'outils web..."
    
    cd "$TOOLS_DIR"
    
    # OWASP ZAP
    
    
    # XSStrike
    if [ ! -d "XSStrike" ]; then
        git clone https://github.com/s0md3v/XSStrike.git
        cd XSStrike
        pip3 install -r requirements.txt 2>/dev/null || true
        cd ..
    fi
    
    # Burp Suite Community (script de téléchargement)
    if [ ! -f "burpsuite_community.jar" ]; then
        print_status "Préparation du téléchargement de Burp Suite Community..."
        echo "#!/bin/bash" > download-burp.sh
        echo "wget 'https://portswigger.net/burp/releases/download?product=community&type=Jar' -O burpsuite_community.jar" >> download-burp.sh
        chmod +x download-burp.sh
    fi
    
    # Commix
    if [ ! -d "commix" ]; then
        git clone https://github.com/commixproject/commix.git
        cd commix
        python3 setup.py install 2>/dev/null || true
        cd ..
    fi
    
    # WPScan
    if ! command -v wpscan &> /dev/null; then
        apt-get install -y -qq wpscan
    fi
    
    print_success "Outils web installés"
}

# Installation d'outils de post-exploitation
install_post_exploit_tools() {
    print_status "Installation d'outils de post-exploitation..."
    
    cd "$TOOLS_DIR"
    
    # LinPEAS
    if [ ! -f "linpeas.sh" ]; then
        wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh || true
        chmod +x linpeas.sh 2>/dev/null || true
    fi
    
    # WinPEAS
    if [ ! -f "winPEAS.exe" ]; then
        wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe || true
    fi
    
    # Mimikatz
    if [ ! -d "mimikatz" ]; then
        mkdir mimikatz
        cd mimikatz
        wget -q https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip || true
        if [ -f "mimikatz_trunk.zip" ]; then
            unzip -q mimikatz_trunk.zip 2>/dev/null || true
            rm mimikatz_trunk.zip
        fi
        cd ..
    fi
    
    # PowerSploit
    if [ ! -d "PowerSploit" ]; then
        git clone https://github.com/PowerShellMafia/PowerSploit.git
    fi
    
    # BloodHound
    if [ ! -d "BloodHound" ]; then
        print_status "Installation de BloodHound..."
        wget -q https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip -O bloodhound.zip || true
        if [ -f "bloodhound.zip" ]; then
            unzip -q bloodhound.zip
            mv BloodHound-linux-x64 BloodHound
            rm bloodhound.zip
        fi
    fi
    
    # Impacket
    pip3 install impacket --break-system-packages 2>/dev/null || true
    
    print_success "Outils de post-exploitation installés"
}

# Installation d'outils Python personnalisés
install_python_tools() {
    print_status "Installation d'outils Python..."
    
    # Mise à jour pip
    pip3 install --upgrade pip
    
    # Outils Python essentiels
    pip3 install --break-system-packages \
        scapy \
        requests \
        beautifulsoup4 \
        selenium \
        paramiko \
        pycryptodome \
        netaddr \
        dnspython \
        python-nmap \
        impacket \
        ldap3 \
        flask \
        flask-socketio \
        websockets \
        aiohttp \
        asyncio \
        colorama \
        tabulate \
        rich 2>/dev/null || \
    pip3 install --break-system-packages \
        scapy \
        requests \
        beautifulsoup4 \
        selenium \
        paramiko \
        pycryptodome \
        netaddr \
        dnspython \
        python-nmap \
        impacket \
        ldap3 \
        flask \
        flask-socketio \
        websockets \
        aiohttp \
        colorama \
        tabulate \
        rich 2>/dev/null || true
    
    # Installation spéciale pour Python2 (si nécessaire)
    if command -v python2 &> /dev/null; then
        print_status "Installation d'outils Python2..."
        cd /tmp
        curl -k https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py 2>/dev/null || true
        if [ -f "get-pip.py" ]; then
            python2 get-pip.py 2>/dev/null || true
            python2 -m pip install scapy 2>/dev/null || true
        fi
    fi
    
    print_success "Outils Python installés"
}

# Configuration spécifique pour l'intégration dashboard web
configure_web_integration() {
    if [ "$WEB_TOOLS_INTEGRATED" = false ]; then
        print_status "Dashboard web non disponible, configuration classique"
        return 0
    fi
    
    print_status "Configuration de l'intégration avec le dashboard web..."
    
    # Créer un fichier de configuration des outils pour l'API
    cat > "$TOOLS_DIR/tools-config.json" << 'EOF'
{
  "tools": {
    "nmap": {
      "path": "/usr/bin/nmap",
      "category": "recon",
      "description": "Network mapper - Scanner réseau",
      "args_example": "-sS -O target"
    },
    "masscan": {
      "path": "/usr/bin/masscan",
      "category": "recon", 
      "description": "Fast port scanner",
      "args_example": "-p80,443 --rate=1000 target"
    },
    "wifite": {
      "path": "/usr/bin/wifite",
      "category": "wifi",
      "description": "Automated WiFi attack tool",
      "args_example": "--wpa --dict /usr/share/wordlists/rockyou.txt"
    },
    "aircrack-ng": {
      "path": "/usr/bin/aircrack-ng",
      "category": "wifi",
      "description": "WiFi WEP/WPA cracking tool",
      "args_example": "-w wordlist.txt capture.cap"
    },
    "reaver": {
      "path": "/usr/bin/reaver",
      "category": "wifi",
      "description": "WPS attack tool",
      "args_example": "-i wlan1mon -b TARGET_BSSID -vv"
    },
    "bully": {
      "path": "/usr/bin/bully",
      "category": "wifi", 
      "description": "WPS brute force tool",
      "args_example": "wlan1mon -b TARGET_BSSID -v 3"
    },
    "nikto": {
      "path": "/usr/bin/nikto",
      "category": "web",
      "description": "Web vulnerability scanner",
      "args_example": "-h target.com"
    },
    "gobuster": {
      "path": "/usr/bin/gobuster",
      "category": "web",
      "description": "Directory/file brute forcer",
      "args_example": "dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt"
    },
    "sqlmap": {
      "path": "/usr/bin/sqlmap",
      "category": "web",
      "description": "SQL injection testing tool",
      "args_example": "-u 'http://target.com/page?id=1' --dbs"
    },
    "hydra": {
      "path": "/usr/bin/hydra",
      "category": "password",
      "description": "Password brute force tool",
      "args_example": "-l admin -P passwords.txt ssh://target.com"
    },
    "john": {
      "path": "/usr/bin/john",
      "category": "password",
      "description": "Password hash cracker",
      "args_example": "--wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"
    },
    "hashcat": {
      "path": "/usr/bin/hashcat",
      "category": "password",
      "description": "Advanced password recovery",
      "args_example": "-m 0 -a 0 hashes.txt rockyou.txt"
    },
    "medusa": {
      "path": "/usr/bin/medusa",
      "category": "password",
      "description": "Parallel password cracker",
      "args_example": "-h target.com -u admin -P passwords.txt -M ssh"
    },
    "msfconsole": {
      "path": "/usr/bin/msfconsole",
      "category": "exploit",
      "description": "Metasploit Framework console",
      "args_example": "-q"
    },
    "wireshark": {
      "path": "/usr/bin/wireshark",
      "category": "network",
      "description": "Network protocol analyzer",
      "args_example": "-i wlan1"
    },
    "ettercap": {
      "path": "/usr/bin/ettercap",
      "category": "network",
      "description": "Network sniffer/interceptor",
      "args_example": "-T -M arp:remote /192.168.1.1// /192.168.1.100//"
    },
    "bettercap": {
      "path": "/usr/bin/bettercap",
      "category": "network",
      "description": "Network attack framework",
      "args_example": "-iface wlan1"
    },
    "tcpdump": {
      "path": "/usr/bin/tcpdump",
      "category": "network",
      "description": "Packet analyzer",
      "args_example": "-i wlan1 -w capture.pcap"
    },
    "wifipumpkin3": {
      "path": "/opt/rasppunzel-tools/wifipumpkin3/wifipumpkin3",
      "category": "wifi",
      "description": "Framework for Rogue Wi-Fi Access Point Attack",
      "args_example": "--help"
    },
    "wifiphisher": {
      "path": "/opt/rasppunzel-tools/wifiphisher/bin/wifiphisher",
      "category": "wifi",
      "description": "Rogue Access Point Framework",
      "args_example": "-aI wlan1 -jI wlan0"
    },
    "fluxion": {
      "path": "/opt/rasppunzel-tools/fluxion/fluxion",
      "category": "wifi",
      "description": "WPA/WPA2 security auditing and social engineering tool",
      "args_example": ""
    },
    "eaphammer": {
      "path": "/opt/rasppunzel-tools/eaphammer/eaphammer",
      "category": "wifi",
      "description": "Targeted evil twin attacks against WPA2-Enterprise networks",
      "args_example": "--cert-wizard"
    },
    "airgeddon": {
      "path": "/opt/rasppunzel-tools/airgeddon/airgeddon.sh",
      "category": "wifi",
      "description": "Multi-use bash script for Linux systems to audit wireless networks",
      "args_example": ""
    }
  }
}
EOF
    
    # Créer des scripts de lancement optimisés pour l'API
    mkdir -p "$TOOLS_DIR/api-launchers"
    
    # Script générique de lancement pour l'API
    cat > "$TOOLS_DIR/api-launchers/launch-tool.sh" << 'EOF'
#!/bin/bash
# Script de lancement générique pour l'API RaspPunzel

TOOL_NAME=$1
TOOL_ARGS=$2
LOG_FILE="/var/log/rasppunzel/tools.log"

# Créer le dossier de logs s'il n'existe pas
mkdir -p /var/log/rasppunzel

# Logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Vérifier que l'outil existe
if ! command -v "$TOOL_NAME" &> /dev/null; then
    log_message "ERREUR: Outil $TOOL_NAME non trouvé"
    echo "ERREUR: Outil $TOOL_NAME non installé"
    exit 1
fi

# Lancer l'outil avec les arguments
log_message "Lancement de $TOOL_NAME avec args: $TOOL_ARGS"
exec "$TOOL_NAME" $TOOL_ARGS 2>&1
EOF
    
    chmod +x "$TOOLS_DIR/api-launchers/launch-tool.sh"
    
    # Script pour les outils dans /opt/rasppunzel-tools
    cat > "$TOOLS_DIR/api-launchers/launch-custom-tool.sh" << 'EOF'
#!/bin/bash
# Script de lancement pour outils personnalisés

TOOL_PATH=$1
shift
TOOL_ARGS="$@"
LOG_FILE="/var/log/rasppunzel/tools.log"

mkdir -p /var/log/rasppunzel

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

if [ ! -f "$TOOL_PATH" ] && [ ! -d "$TOOL_PATH" ]; then
    log_message "ERREUR: Outil $TOOL_PATH non trouvé"
    echo "ERREUR: Outil $TOOL_PATH non installé"
    exit 1
fi

log_message "Lancement de $TOOL_PATH avec args: $TOOL_ARGS"

# Gestion spéciale selon le type d'outil
if [[ "$TOOL_PATH" == *"python"* ]] || [[ "$TOOL_PATH" == *".py" ]]; then
    exec python3 "$TOOL_PATH" $TOOL_ARGS 2>&1
elif [[ "$TOOL_PATH" == *".sh" ]]; then
    exec bash "$TOOL_PATH" $TOOL_ARGS 2>&1
else
    exec "$TOOL_PATH" $TOOL_ARGS 2>&1
fi
EOF
    
    chmod +x "$TOOLS_DIR/api-launchers/launch-custom-tool.sh"
    
    print_success "Intégration dashboard web configurée"
}

# Configuration des alias et raccourcis
setup_aliases() {
    print_status "Configuration des alias..."
    
    local alias_file="/home/admin/.bashrc"
    [ -f "/home/kali/.bashrc" ] && alias_file="/home/kali/.bashrc"
    [ -f "/home/pi/.bashrc" ] && alias_file="/home/pi/.bashrc"
    
    # Sauvegarder le bashrc existant
    cp "$alias_file" "${alias_file}.backup" 2>/dev/null || true
    
    cat >> "$alias_file" << 'EOF'

# === RaspPunzel Aliases ===
alias ll='ls -alF'
alias la='ls -A'  
alias l='ls -CF'
alias grep='grep --color=auto'

# Raccourcis outils
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias airmon='airmon-ng'
alias airodump='airodump-ng'
alias aircrack='aircrack-ng'
alias wifite='wifite'
alias msfconsole='msfconsole -q'

# Navigation outils
alias cdtools='cd /opt/rasppunzel-tools'
alias cdscripts='cd /opt/rasppunzel-scripts'
alias cdlogs='cd /var/log/rasppunzel'

# Status système
alias status='systemctl status hostapd dnsmasq nginx ssh'
alias netstat='ss -tuln'
alias psgrep='ps aux | grep'

# Raccourcis WiFi monitoring
alias start-monitor='airmon-ng start wlan1'
alias stop-monitor='airmon-ng stop wlan1mon'
alias wifi-scan='airodump-ng wlan1mon'

# Dashboard web (si installé)
alias dashboard='make start-web'
alias webstatus='make web-logs'
alias restart-web='make restart-web'
EOF

    # Alias pour root aussi
    cp "$alias_file" /root/.bashrc 2>/dev/null || true
    
    print_success "Alias configurés"
}

# Création de scripts de lancement rapide
create_launcher_scripts() {
    print_status "Création des scripts de lancement..."
    
    mkdir -p /opt/rasppunzel-scripts/launchers
    
    # Script pour Metasploit
    cat > /opt/rasppunzel-scripts/launchers/msf.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Metasploit Framework..."
cd /usr/share/metasploit-framework
./msfconsole -q
EOF
    
    # Script pour Wifite
    cat > /opt/rasppunzel-scripts/launchers/wifite.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Wifite..."
if [ -d "/opt/rasppunzel-tools/wifite" ]; then
    cd /opt/rasppunzel-tools/wifite
    python3 Wifite.py "$@"
else
    wifite "$@"
fi
EOF
    
    # Script pour Bettercap
    cat > /opt/rasppunzel-scripts/launchers/bettercap.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Bettercap..."
if [ $# -eq 0 ]; then
    bettercap -iface wlan1
else
    bettercap "$@"
fi
EOF
    
    # Script pour Aircrack-ng suite
    cat > /opt/rasppunzel-scripts/launchers/aircrack.sh << 'EOF'
#!/bin/bash
echo "=== Aircrack-ng Suite ==="
echo "1. Airmon-ng (Monitor mode)"
echo "2. Airodump-ng (Capture)"
echo "3. Aircrack-ng (Crack)"
echo "4. Aireplay-ng (Attack)"
read -p "Choix [1-4]: " choice

case $choice in
    1) airmon-ng ;;
    2) read -p "Interface (ex: wlan1mon): " iface; airodump-ng $iface ;;
    3) read -p "Fichier capture: " file; aircrack-ng $file ;;
    4) aireplay-ng ;;
    *) echo "Choix invalide" ;;
esac
EOF

    # Script pour Wifipumpkin3
    cat > /opt/rasppunzel-scripts/launchers/wifipumpkin3.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Wifipumpkin3..."
cd /opt/rasppunzel-tools/wifipumpkin3
python3 wifipumpkin3 "$@"
EOF

    # Script pour Wifiphisher
    cat > /opt/rasppunzel-scripts/launchers/wifiphisher.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Wifiphisher..."
cd /opt/rasppunzel-tools/wifiphisher
python3 bin/wifiphisher "$@"
EOF

    # Script pour Fluxion
    cat > /opt/rasppunzel-scripts/launchers/fluxion.sh << 'EOF'
#!/bin/bash
echo "Démarrage de Fluxion..."
cd /opt/rasppunzel-tools/fluxion
./fluxion
EOF

    # Script pour EAPHammer
    cat > /opt/rasppunzel-scripts/launchers/eaphammer.sh << 'EOF'
#!/bin/bash
echo "Démarrage d'EAPHammer..."
cd /opt/rasppunzel-tools/eaphammer
python3 eaphammer "$@"
EOF

    # Script pour reconnaissance
    cat > /opt/rasppunzel-scripts/launchers/recon.sh << 'EOF'
#!/bin/bash
echo "=== Outils de Reconnaissance ==="
echo "1. Nmap - Scan réseau"
echo "2. TheHarvester - OSINT"
echo "3. Sublist3r - Énumération sous-domaines"
echo "4. Recon-ng - Framework reconnaissance"
echo "5. Amass - Découverte d'actifs"
read -p "Choix [1-5]: " choice

case $choice in
    1) read -p "Cible: " target; nmap -T4 -A $target ;;
    2) read -p "Domaine: " domain; cd /opt/rasppunzel-tools/theHarvester && python3 theHarvester.py -d $domain -b all ;;
    3) read -p "Domaine: " domain; cd /opt/rasppunzel-tools/Sublist3r && python3 sublist3r.py -d $domain ;;
    4) cd /opt/rasppunzel-tools/recon-ng && python3 recon-ng ;;
    5) read -p "Domaine: " domain; amass enum -d $domain ;;
    *) echo "Choix invalide" ;;
esac
EOF

    # Script pour outils web
    cat > /opt/rasppunzel-scripts/launchers/webtools.sh << 'EOF'
#!/bin/bash
echo "=== Outils Web ==="
echo "1. Nikto - Scanner vulnérabilités web"
echo "2. Gobuster - Brute force directories"
echo "3. SQLMap - Injection SQL"
echo "4. XSStrike - XSS testing"
echo "5. WPScan - WordPress scanner"
read -p "Choix [1-5]: " choice

case $choice in
    1) read -p "URL cible: " url; nikto -h $url ;;
    2) read -p "URL cible: " url; gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt ;;
    3) read -p "URL cible: " url; sqlmap -u $url --dbs ;;
    4) read -p "URL cible: " url; cd /opt/rasppunzel-tools/XSStrike && python3 xsstrike.py -u $url ;;
    5) read -p "URL cible: " url; wpscan --url $url ;;
    *) echo "Choix invalide" ;;
esac
EOF

    # Script spécial pour dashboard web (si disponible)
    if [ "$WEB_TOOLS_INTEGRATED" = true ]; then
        cat > /opt/rasppunzel-scripts/launchers/web-tools.sh << 'EOF'
#!/bin/bash
echo "=== Outils RaspPunzel Dashboard Web ==="
echo "1. Démarrer dashboard web"
echo "2. Voir logs dashboard"
echo "3. Status dashboard"
echo "4. Redémarrer dashboard"
echo "5. Arrêter dashboard"
read -p "Choix [1-5]: " choice

case $choice in
    1) make start-web ;;
    2) make web-logs ;;
    3) make status | grep -E "(rasppunzel-web|Dashboard)" ;;
    4) make restart-web ;;
    5) make stop-web ;;
    *) echo "Choix invalide" ;;
esac
EOF
    fi

    # Script de menu principal
    cat > /opt/rasppunzel-scripts/launchers/menu.sh << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════╗"
    echo "║            RaspPunzel Menu           ║"
    echo "║         Pentest Tools Launcher       ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

show_menu() {
    echo -e "${YELLOW}=== Catégories d'outils ===${NC}"
    echo "1. WiFi & Sans-fil"
    echo "2. Reconnaissance & OSINT" 
    echo "3. Web & Applications"
    echo "4. Exploitation & Frameworks"
    echo "5. Post-exploitation"
    echo "6. Cracking & Mots de passe"
    echo "7. Réseau & Capture"
    echo "8. Dashboard Web (si disponible)"
    echo "9. Status système"
    echo "0. Quitter"
    echo
}

wifi_menu() {
    echo -e "${GREEN}=== Outils WiFi ===${NC}"
    echo "1. Wifite (automatique)"
    echo "2. Aircrack-ng suite"
    echo "3. Wifipumpkin3 (AP malveillant)"
    echo "4. Wifiphisher (phishing WiFi)"
    echo "5. Fluxion (captive portal)"
    echo "6. EAPHammer (WPA2-Enterprise)"
    echo "7. Bettercap (MitM)"
    echo "8. Retour"
    read -p "Choix: " wifi_choice
    
    case $wifi_choice in
        1) /opt/rasppunzel-scripts/launchers/wifite.sh ;;
        2) /opt/rasppunzel-scripts/launchers/aircrack.sh ;;
        3) /opt/rasppunzel-scripts/launchers/wifipumpkin3.sh ;;
        4) /opt/rasppunzel-scripts/launchers/wifiphisher.sh ;;
        5) /opt/rasppunzel-scripts/launchers/fluxion.sh ;;
        6) /opt/rasppunzel-scripts/launchers/eaphammer.sh ;;
        7) /opt/rasppunzel-scripts/launchers/bettercap.sh ;;
        8) return ;;
        *) echo "Choix invalide" ;;
    esac
}

main_loop() {
    while true; do
        clear
        show_banner
        show_menu
        read -p "Votre choix: " choice
        
        case $choice in
            1) wifi_menu ;;
            2) /opt/rasppunzel-scripts/launchers/recon.sh ;;
            3) /opt/rasppunzel-scripts/launchers/webtools.sh ;;
            4) /opt/rasppunzel-scripts/launchers/msf.sh ;;
            5) echo "Outils post-exploitation disponibles dans /opt/rasppunzel-tools" ;;
            6) echo "John, Hashcat, Hydra disponibles via commandes directes" ;;
            7) echo "Wireshark, tcpdump, ettercap disponibles" ;;
            8) [ -f "/opt/rasppunzel-scripts/launchers/web-tools.sh" ] && /opt/rasppunzel-scripts/launchers/web-tools.sh || echo "Dashboard web non disponible" ;;
            9) systemctl status hostapd dnsmasq ssh nginx | grep -E "(Active|Main)" ;;
            0) echo "Au revoir!"; exit 0 ;;
            *) echo "Choix invalide"; sleep 2 ;;
        esac
        
        echo
        read -p "Appuyez sur Entrée pour continuer..."
    done
}

main_loop
EOF
    
    chmod +x /opt/rasppunzel-scripts/launchers/*.sh
    
    # Créer un lien symbolique pour accès facile
    ln -sf /opt/rasppunzel-scripts/launchers/menu.sh /usr/local/bin/rasppunzel-menu
    
    print_success "Scripts de lancement créés"
    print_status "Menu principal accessible via: rasppunzel-menu"
}

# Installation de wordlists
install_wordlists() {
    print_status "Installation des wordlists..."
    
    # Wordlists standard Kali
    apt-get install -y -qq wordlists
    
    # Créer le dossier wordlists personnalisé
    mkdir -p /opt/rasppunzel-wordlists
    cd /opt/rasppunzel-wordlists
    
    # SecLists
    if [ ! -d "SecLists" ]; then
        git clone https://github.com/danielmiessler/SecLists.git
    fi
    
    # Passwords communes
    if [ ! -f "common-passwords.txt" ]; then
        wget -q https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top-12-Million-Passwords.txt -O common-passwords.txt || true
    fi
    
    # WiFi passwords
    if [ ! -f "wifi-passwords.txt" ]; then
        wget -q https://raw.githubusercontent.com/kennyn510/wpa2-wordlists/master/Wordlists/WPA2-GPU.txt -O wifi-passwords.txt || true
    fi
    
    print_success "Wordlists installés dans /opt/rasppunzel-wordlists"
}

# Configuration des logs
setup_logging() {
    print_status "Configuration du système de logs..."
    
    # Créer les dossiers de logs
    mkdir -p /var/log/rasppunzel
    touch /var/log/rasppunzel/tools.log
    touch /var/log/rasppunzel/access.log
    touch /var/log/rasppunzel/system.log
    
    # Configuration logrotate
    cat > /etc/logrotate.d/rasppunzel << 'EOF'
/var/log/rasppunzel/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    
    # Script de monitoring des logs
    cat > /opt/rasppunzel-scripts/view-logs.sh << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/rasppunzel"

echo "=== Logs RaspPunzel ==="
echo "1. Logs outils (tools.log)"
echo "2. Logs accès (access.log)"  
echo "3. Logs système (system.log)"
echo "4. Tous les logs"
echo "5. Logs temps réel (tail -f)"
read -p "Choix: " choice

case $choice in
    1) less "$LOG_DIR/tools.log" ;;
    2) less "$LOG_DIR/access.log" ;;
    3) less "$LOG_DIR/system.log" ;;
    4) tail -n 50 "$LOG_DIR"/*.log ;;
    5) tail -f "$LOG_DIR"/*.log ;;
    *) echo "Choix invalide" ;;
esac
EOF
    
    chmod +x /opt/rasppunzel-scripts/view-logs.sh
    
    # Permissions
    chown -R root:adm /var/log/rasppunzel
    chmod 755 /var/log/rasppunzel
    chmod 644 /var/log/rasppunzel/*.log
    
    print_success "Système de logs configuré"
}

# Vérification finale des installations
verify_installation() {
    print_status "Vérification des installations..."
    
    local errors=0
    
    # Vérification des commandes essentielles
    commands=("nmap" "aircrack-ng" "msfconsole" "john" "hashcat" "hydra" "gobuster" "nikto" "sqlmap")
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Commande manquante: $cmd"
            ((errors++))
        fi
    done
    
    # Vérification des répertoires
    directories=("$TOOLS_DIR" "/opt/rasppunzel-scripts" "/var/log/rasppunzel")
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            print_error "Répertoire manquant: $dir"
            ((errors++))
        fi
    done
    
    # Vérification spécifique dashboard web
    if [ "$WEB_TOOLS_INTEGRATED" = true ]; then
        if [ -f "$TOOLS_DIR/tools-config.json" ]; then
            print_success "Configuration dashboard web OK"
        else
            print_warning "Configuration dashboard web incomplète"
            ((errors++))
        fi
    fi
    
    # Vérification des outils avancés
    advanced_tools=("$TOOLS_DIR/wifipumpkin3" "$TOOLS_DIR/wifiphisher" "$TOOLS_DIR/fluxion")
    for tool in "${advanced_tools[@]}"; do
        if [ ! -d "$tool" ]; then
            print_warning "Outil avancé non installé: $(basename $tool)"
        fi
    done
    
    if [ $errors -eq 0 ]; then
        print_success "Toutes les vérifications essentielles sont OK"
        if [ "$WEB_TOOLS_INTEGRATED" = true ]; then
            print_status "Dashboard web: Outils intégrés et prêts"
        fi
    else
        print_warning "$errors erreur(s) critique(s) détectée(s)"
    fi
    
    return $errors
}

# Nettoyage post-installation
cleanup_installation() {
    print_status "Nettoyage post-installation..."
    
    apt-get autoremove -y -qq
    apt-get autoclean
    
    # Nettoyage des fichiers temporaires
    rm -rf /tmp/rasppunzel-*
    rm -rf /tmp/get-pip.py
    rm -rf /tmp/amass*
    
    # Optimisation des permissions
    chown -R admin:admin /home/admin 2>/dev/null || chown -R kali:kali /home/kali 2>/dev/null || chown -R pi:pi /home/pi 2>/dev/null || true
    chmod -R 755 /opt/rasppunzel-scripts 2>/dev/null || true
    chmod -R 755 "$TOOLS_DIR" 2>/dev/null || true
    
    # Mise à jour de la base de données locate
    updatedb 2>/dev/null || true
    
    print_success "Nettoyage terminé"
}

# Affichage du résumé d'installation
show_installation_summary() {
    echo
    print_success "=== RÉSUMÉ INSTALLATION OUTILS ==="
    echo
    
    # Outils de base
    print_status "Outils installés dans le système:"
    local system_tools=("nmap" "masscan" "aircrack-ng" "wifite" "nikto" "gobuster" "sqlmap" "hydra" "john" "hashcat" "msfconsole")
    for tool in "${system_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
        fi
    done
    
    echo
    # Outils avancés
    print_status "Outils avancés dans $TOOLS_DIR:"
    if [ -d "$TOOLS_DIR" ]; then
        ls -1 "$TOOLS_DIR" 2>/dev/null | head -10 | while read tool; do
            echo -e "  ${BLUE}•${NC} $tool"
        done
        
        local tool_count=$(ls -1 "$TOOLS_DIR" 2>/dev/null | wc -l)
        if [ $tool_count -gt 10 ]; then
            echo -e "  ${YELLOW}... et $((tool_count - 10)) autres outils${NC}"
        fi
    fi
    
    echo
    # Intégration dashboard web
    if [ "$WEB_TOOLS_INTEGRATED" = true ]; then
        print_status "Intégration Dashboard Web:"
        echo -e "  ${GREEN}✓${NC} Configuration API créée"
        echo -e "  ${GREEN}✓${NC} Scripts de lancement optimisés"  
        echo -e "  ${GREEN}✓${NC} Outils accessibles via interface web"
        echo -e "  ${BLUE}→${NC} Démarrez avec: make start-web"
    else
        print_status "Installation classique - Dashboard web non disponible"
    fi
    
    echo
    print_status "Raccourcis disponibles:"
    echo -e "  ${GREEN}•${NC} Menu principal: rasppunzel-menu"
    echo -e "  ${GREEN}•${NC} Scripts: /opt/rasppunzel-scripts/launchers/"
    echo -e "  ${GREEN}•${NC} Logs: /opt/rasppunzel-scripts/view-logs.sh"
    echo -e "  ${GREEN}•${NC} Wordlists: /opt/rasppunzel-wordlists"
    
    echo
    print_success "Installation des outils terminée!"
    echo -e "${YELLOW}Redémarrage recommandé pour activer tous les alias${NC}"
    echo -e "${BLUE}Tapez 'rasppunzel-menu' pour commencer${NC}"
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    echo -e "${BLUE}=== Installation Outils RaspPunzel ===${NC}"
    if [ "$WEB_TOOLS_INTEGRATED" = true ]; then
        echo -e "${GREEN}Mode: Intégration Dashboard Web${NC}"
    else
        echo -e "${YELLOW}Mode: Installation Classique${NC}"
    fi
    echo
    
    print_status "Démarrage de l'installation..."
    sleep 2
    
    # Installation des outils
    install_system_tools
    install_wifi_tools
    install_frameworks
    install_advanced_wifi_tools
    install_recon_tools
    install_web_tools
    install_post_exploit_tools
    install_python_tools
    install_wordlists
    
    # Configuration
    configure_web_integration
    setup_aliases
    create_launcher_scripts
    setup_logging
    
    # Finalisation
    verify_installation
    cleanup_installation
    show_installation_summary
}

# Point d'entrée avec gestion des arguments
case "${1:-}" in
    --web-integration)
        WEB_TOOLS_INTEGRATED=true
        main
        ;;
    --classic)
        WEB_TOOLS_INTEGRATED=false
        main
        ;;
    --verify)
        detect_web_dashboard
        verify_installation
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --web-integration  Forcer l'intégration dashboard web"
        echo "  --classic          Installation classique sans dashboard"
        echo "  --verify           Vérifier l'installation existante" 
        echo "  --help             Afficher cette aide"
        echo ""
        echo "Par défaut, détection automatique du dashboard web"
        ;;
    "")
        detect_web_dashboard
        main
        ;;
    *)
        print_error "Option inconnue: $1"
        echo "Utilisez --help pour voir les options disponibles"
        exit 1
        ;;
esac