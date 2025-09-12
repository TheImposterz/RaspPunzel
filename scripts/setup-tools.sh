#!/bin/bash

# =============================================================================
# RaspPunzel - Installation des Outils de Pentest
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

# Installation des outils système de base
install_system_tools() {
    print_status "Installation des outils système de base..."
    
    apt-get update -qq
    
    # Outils système essentiels
    apt-get install -y -qq \
        curl wget git vim nano htop iotop \
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
    print_status "Installation des frameworks..."
    
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
    
    print_success "Outils de reconnaissance installés"
}

# Installation d'outils d'exploitation web
install_web_tools() {
    print_status "Installation d'outils web..."
    
    cd "$TOOLS_DIR"
    
    # OWASP ZAP
    if [ ! -d "zaproxy" ]; then
        wget -q https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2.12.0_Linux.tar.gz
        tar -xzf ZAP_2.12.0_Linux.tar.gz
        mv ZAP_2.12.0 zaproxy
        rm ZAP_2.12.0_Linux.tar.gz
    fi
    
    # XSStrike
    if [ ! -d "XSStrike" ]; then
        git clone https://github.com/s0md3v/XSStrike.git
        cd XSStrike
        pip3 install -r requirements.txt 2>/dev/null || true
        cd ..
    fi
    
    print_success "Outils web installés"
}

# Installation d'outils de post-exploitation
install_post_exploit_tools() {
    print_status "Installation d'outils de post-exploitation..."
    
    cd "$TOOLS_DIR"
    
    # LinPEAS
    if [ ! -f "linpeas.sh" ]; then
        wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
        chmod +x linpeas.sh
    fi
    
    # WinPEAS
    if [ ! -f "winPEAS.exe" ]; then
        wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe
    fi
    
    # Mimikatz
    if [ ! -d "mimikatz" ]; then
        mkdir mimikatz
        cd mimikatz
        wget -q https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
        unzip -q mimikatz_trunk.zip
        rm mimikatz_trunk.zip
        cd ..
    fi
    
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
        bloodhound \
        crackmapexec \
        ldap3 \
        flask \
        socketio
    
    print_success "Outils Python installés"
}

# Configuration des alias et raccourcis
setup_aliases() {
    print_status "Configuration des alias..."
    
    cat >> /home/kali/.bashrc << 'EOF'

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
alias wifite='python3 /opt/rasppunzel-tools/wifite/Wifite.py'
alias empire='/opt/rasppunzel-tools/Empire/empire'
alias msfconsole='msfconsole -q'

# Navigation outils
alias cdtools='cd /opt/rasppunzel-tools'
alias cdscripts='cd /opt/rasppunzel-scripts'
alias cdlogs='cd /var/log/rasppunzel'

# Status système
alias status='systemctl status hostapd dnsmasq nginx ssh'
alias netstat='ss -tuln'
alias psgrep='ps aux | grep'
EOF

    # Alias pour root aussi
    cp /home/kali/.bashrc /root/.bashrc 2>/dev/null || true
    
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
cd /opt/rasppunzel-tools
if [ -d "wifite" ]; then
    python3 wifite/Wifite.py "$@"
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
    2) airodump-ng ;;
    3) aircrack-ng ;;
    4) aireplay-ng ;;
    *) echo "Choix invalide" ;;
esac
EOF
    
    chmod +x /opt/rasppunzel-scripts/launchers/*.sh
    
    print_success "Scripts de lancement créés"
}

# Vérification finale des installations
verify_installation() {
    print_status "Vérification des installations..."
    
    local errors=0
    
    # Vérification des commandes essentielles
    commands=("nmap" "aircrack-ng" "msfconsole" "john" "hashcat" "hydra" "gobuster")
    
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Commande manquante: $cmd"
            ((errors++))
        fi
    done
    
    # Vérification des répertoires
    if [ ! -d "$TOOLS_DIR" ]; then
        print_error "Répertoire $TOOLS_DIR manquant"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        print_success "Toutes les vérifications sont OK"
    else
        print_warning "$errors erreur(s) détectée(s)"
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
    
    # Optimisation des permissions
    chown -R kali:kali /home/kali 2>/dev/null || true
    chmod -R 755 /opt/rasppunzel-scripts 2>/dev/null || true
    
    print_success "Nettoyage terminé"
}

# Fonction principale
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    echo -e "${BLUE}=== Installation Outils RaspPunzel ===${NC}"
    echo
    
    install_system_tools
    install_wifi_tools
    install_frameworks
    install_advanced_wifi_tools
    install_recon_tools
    install_web_tools
    install_post_exploit_tools
    install_python_tools
    setup_aliases
    create_launcher_scripts
    verify_installation
    cleanup_installation
    
    echo
    print_success "Installation des outils terminée!"
    print_status "Outils disponibles dans: $TOOLS_DIR"
    print_status "Scripts dans: /opt/rasppunzel-scripts"
}

# Point d'entrée
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi