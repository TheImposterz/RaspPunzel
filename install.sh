#!/bin/bash
# =================================================================================================
# RaspPunzel - Lightweight Network Pivot with Ligolo-ng
# =================================================================================================
# Main Installation Script - Interactive installation that configures headless operation
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Project paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"
CONFIG_DIR="${PROJECT_ROOT}/config"
INSTALL_LOG="/var/log/rasppunzel-install.log"

# =================================================================================================
# Helper Functions
# =================================================================================================

print_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔═════════════════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                                                 ║"
    echo "║                              🚀 RaspPunzel Installation 🚀                                      ║"
    echo "║                                                                                                 ║"
    echo "║        Lightweight Pwnbox installer RogueAP, tunneling with ligolo and WiFi Pentest             ║"
    echo "║                                                                                                 ║"
    echo "╚═════════════════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${INSTALL_LOG}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

check_requirements() {
    log "INFO" "Checking system requirements..."
    
    if [[ ! -f /etc/os-release ]]; then
        log "ERROR" "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    log "INFO" "Detected OS: ${PRETTY_NAME}"
    
    ARCH=$(uname -m)
    log "INFO" "Architecture: ${ARCH}"
    
    if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "armv7l" && "${ARCH}" != "x86_64" ]]; then
        log "ERROR" "Unsupported architecture: ${ARCH}"
        exit 1
    fi
    
    AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
    if [[ ${AVAILABLE_SPACE} -lt 2097152 ]]; then
        log "WARN" "Low disk space detected. At least 2GB recommended."
    fi
    
    log "INFO" "System requirements check passed"
}

load_config() {
    log "INFO" "Loading configuration..."
    
    if [[ -f "${PROJECT_ROOT}/config.sh" ]]; then
        source "${PROJECT_ROOT}/config.sh"
        log "INFO" "Configuration loaded from config.sh"
    else
        log "ERROR" "config.sh not found!"
        exit 1
    fi
}

# =================================================================================================
# Interactive Configuration
# =================================================================================================

ask_headless_mode() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              Headless Mode Configuration${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Headless mode removes the graphical interface and configures${NC}"
    echo -e "${YELLOW}the system for unattended operation:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Remove GUI (X11, Desktop Environment)"
    echo -e "  ${GREEN}✓${NC} Auto-login to console at boot"
    echo -e "  ${GREEN}✓${NC} Auto-start all services"
    echo -e "  ${GREEN}✓${NC} Free ~500MB RAM"
    echo -e "  ${GREEN}✓${NC} Faster boot time"
    echo ""
    echo -e "${YELLOW}Access will be via:${NC}"
    echo -e "  - SSH (recommended)"
    echo -e "  - Serial console"
    echo -e "  - Web dashboard (if enabled)"
    echo ""
    echo -e "${RED}Note: GUI can be restored later if needed${NC}"
    echo ""
    
    read -p "Enable headless mode? [Y/n]: " -r
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        ENABLE_HEADLESS_MODE="true"
        log "INFO" "Headless mode will be enabled"
    else
        ENABLE_HEADLESS_MODE="false"
        log "INFO" "Headless mode disabled - GUI will be kept"
    fi
}

ask_web_dashboard() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              Web Dashboard Configuration${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "The web dashboard provides:"
    echo -e "  ${GREEN}✓${NC} Real-time system monitoring"
    echo -e "  ${GREEN}✓${NC} Service management"
    echo -e "  ${GREEN}✓${NC} Ligolo-ng status and control"
    echo -e "  ${GREEN}✓${NC} Network adapter management"
    echo -e "  ${GREEN}✓${NC} WiFi AP control"
    echo ""
    
    read -p "Install web dashboard? [Y/n]: " -r
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        ENABLE_WEB_DASHBOARD="true"
        log "INFO" "Web dashboard will be installed"
    else
        ENABLE_WEB_DASHBOARD="false"
        log "INFO" "Web dashboard disabled"
    fi
}

ask_certbot() {
    if [[ "${ENABLE_WEB_DASHBOARD}" == "true" ]]; then
        echo ""
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}              SSL Certificate Configuration${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "Certbot can automatically provision and renew SSL certificates"
        echo -e "from Let's Encrypt for secure HTTPS access."
        echo ""
        echo -e "${YELLOW}Requirements:${NC}"
        echo -e "  - A domain name"
        echo -e "  - DNS configured (A record pointing to this server)"
        echo -e "  - DNS API credentials (for DNS-01 challenge)"
        echo ""
        
        read -p "Install Certbot for SSL? [y/N]: " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ENABLE_CERTBOT="true"
            log "INFO" "Certbot will be installed"
        else
            ENABLE_CERTBOT="false"
            log "INFO" "Certbot disabled"
        fi
    else
        ENABLE_CERTBOT="false"
    fi
}

# =================================================================================================
# Installation Functions
# =================================================================================================

install_ligolo() {
    log "INFO" "Installing Ligolo-ng..."
    bash "${SCRIPTS_DIR}/install-ligolo.sh" || {
        log "ERROR" "Ligolo-ng installation failed"
       
    }
}

setup_network() {
    log "INFO" "Configuring network..."
    bash "${SCRIPTS_DIR}/setup-network.sh" || {
        log "ERROR" "Network setup failed"
        
    }
}

install_web_dashboard() {
    if [[ "${ENABLE_WEB_DASHBOARD}" == "true" ]]; then
        log "INFO" "Installing web dashboard..."
        bash "${SCRIPTS_DIR}/install-web-dashboard.sh" || {
            log "ERROR" "Web dashboard installation failed"
           
        }
    else
        log "INFO" "Skipping web dashboard (disabled)"
    fi
}

install_certbot() {
    if [[ "${ENABLE_CERTBOT}" == "true" ]]; then
        log "INFO" "Installing Certbot..."
        bash "${SCRIPTS_DIR}/install-certbot.sh" || {
            log "ERROR" "Certbot installation failed"
            
        }
    else
        log "INFO" "Skipping Certbot (disabled)"
    fi
}

configure_services() {
    log "INFO" "Configuring services..."
    bash "${SCRIPTS_DIR}/service-manager.sh" setup || {
        log "ERROR" "Service configuration failed"
        
    }
}

convert_to_headless() {
    if [[ "${ENABLE_HEADLESS_MODE}" == "true" ]]; then
        log "INFO" "Converting system to headless mode..."
        echo ""
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}              Converting to Headless Mode${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        
        bash "${SCRIPTS_DIR}/convert-to-headless.sh" || {
            log "ERROR" "Headless conversion failed"
            
        }
    else
        log "INFO" "Skipping headless conversion (disabled)"
    fi
}

create_management_scripts() {
    log "INFO" "Creating management scripts..."
    
    ln -sf "${SCRIPTS_DIR}/start-services.sh" /usr/local/bin/rasppunzel-start
    ln -sf "${SCRIPTS_DIR}/stop-services.sh" /usr/local/bin/rasppunzel-stop
    ln -sf "${SCRIPTS_DIR}/service-manager.sh" /usr/local/bin/rasppunzel-manager
    
    chmod +x "${SCRIPTS_DIR}"/*.sh
    chmod +x /usr/local/bin/rasppunzel-*
    
    log "INFO" "Management scripts created"
}

generate_summary() {
    local SUMMARY_FILE="/root/RASPPUNZEL-INFO.txt"
    
    cat > "${SUMMARY_FILE}" <<EOF
═══════════════════════════════════════════════════════════════
                RaspPunzel Installation Summary
═══════════════════════════════════════════════════════════════

Installation Date: $(date '+%Y-%m-%d %H:%M:%S')
Hostname: $(hostname)
IP Addresses: $(hostname -I)

CONFIGURATION:
  Headless Mode: ${ENABLE_HEADLESS_MODE}
  Web Dashboard: ${ENABLE_WEB_DASHBOARD}
  SSL/Certbot: ${ENABLE_CERTBOT}

QUICK START COMMANDS:
  rasppunzel-start    Start all services
  rasppunzel-stop     Stop all services
  rasppunzel-manager  Interactive management menu

LIGOLO-NG:
  Proxy Host: ${LIGOLO_PROXY_HOST}
  Proxy Port: ${LIGOLO_PROXY_PORT}
  Status: systemctl status ligolo-agent

EOF

    if [[ "${ENABLE_WEB_DASHBOARD}" == "true" ]]; then
        cat >> "${SUMMARY_FILE}" <<EOF
WEB DASHBOARD:
  URL: http://$(hostname -I | awk '{print $1}'):8080
  Username: admin
  Password: rasppunzel
  
  ⚠️  IMPORTANT: Change default password after first login!
  Credentials file: /opt/rasppunzel/web/.credentials

EOF
    fi

    if [[ "${ENABLE_HEADLESS_MODE}" == "true" ]]; then
        cat >> "${SUMMARY_FILE}" <<EOF
HEADLESS MODE:
  GUI removed: Yes (~500MB RAM freed)
  Auto-login: Yes (console on tty1)
  Services auto-start: Yes
  
  Access methods:
    - SSH: ssh root@$(hostname -I | awk '{print $1}')
    - Serial console (if available)
    - Web dashboard: http://$(hostname -I | awk '{print $1}'):8080
  
  Recovery:
    If you need GUI back: rasppunzel-restore-gui.sh

EOF
    fi

    cat >> "${SUMMARY_FILE}" <<EOF
SERVICES STATUS:
EOF

    for service in ssh ligolo-agent hostapd dnsmasq rasppunzel-web nginx; do
        if systemctl is-enabled "$service" &>/dev/null; then
            echo "  ✓ $service: enabled" >> "${SUMMARY_FILE}"
        fi
    done

    cat >> "${SUMMARY_FILE}" <<EOF

IMPORTANT FILES:
  Install Log: ${INSTALL_LOG}
  Config: ${PROJECT_ROOT}/config.sh
  Scripts: ${SCRIPTS_DIR}
  This file: ${SUMMARY_FILE}

NEXT STEPS:
  1. Review this summary
  2. REBOOT to apply all changes: reboot
  3. After reboot, services will start automatically
  4. Access via SSH or web dashboard

═══════════════════════════════════════════════════════════════
EOF

    chmod 600 "${SUMMARY_FILE}"
    log "INFO" "Installation summary: ${SUMMARY_FILE}"
}
install_pentest_tools() {
    if [[ "${ENABLE_PENTEST_TOOLS}" == "true" ]]; then
        log "INFO" "Installing pentest WiFi tools..."
        bash "${SCRIPTS_DIR}/install-pentest-tools.sh" || {
            log "ERROR" "Pentest tools installation failed"
        
        }
    else
        log "INFO" "Pentest tools disabled in config"
    fi
}

ask_pentest_tools() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           Pentest WiFi Tools Configuration${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "Install WiFi pentesting tools?"
    echo ""
    echo -e "${YELLOW}This includes:${NC}"
    echo -e "  - Basic: wifite, reaver, bully, mdk4, kismet"
    echo -e "  - Handshake: hcxdumptool, hcxtools, cowpatty"
    echo -e "  - Rogue AP: hostapd-wpe, hostapd-mana"
    echo -e "  - Advanced: Fluxion"
    echo -e "  -  crEAP"
    echo -e "  - Other: Airgeddon, Berate_ap, WPA_Sycophant"
    echo ""
    echo -e "${YELLOW}Note: This will download ~500MB and take 15-30 minutes${NC}"
    echo ""
    
    read -p "Install pentest tools? [Y/n]: " -r
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        ENABLE_PENTEST_TOOLS="true"
        log "INFO" "Pentest tools will be installed"
    else
        ENABLE_PENTEST_TOOLS="false"
        log "INFO" "Pentest tools disabled"
    fi
}


# =================================================================================================
# Main Installation Flow
# =================================================================================================

main() {
    print_banner
    check_root
    
    # Initialize log
    mkdir -p "$(dirname "${INSTALL_LOG}")"
    echo "═══════════════════════════════════════════════════════════════" > "${INSTALL_LOG}"
    echo "RaspPunzel Installation - $(date)" >> "${INSTALL_LOG}"
    echo "═══════════════════════════════════════════════════════════════" >> "${INSTALL_LOG}"
    
    check_requirements
    load_config
    
    echo ""
    echo -e "${GREEN}Welcome to RaspPunzel interactive installation!${NC}"
    echo ""
    echo -e "This installer will:"
    echo -e "  1. Install Ligolo-ng agent"
    echo -e "  2. Configure network and services"
    echo -e "  3. Optionally install web dashboard"
    echo -e "  4. Optionally configure SSL"
    echo -e "  5. Optionally convert to headless mode"
    echo ""
    
    read -p "Continue? [Y/n]: " -r
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo -e "\n${YELLOW}Installation cancelled.${NC}"
        exit 0
    fi
    
    # Interactive questions
    ask_web_dashboard
    ask_certbot
    ask_pentest_tools
    ask_headless_mode
    
    # Show installation plan
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                   Installation Plan${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Ligolo-ng Agent"
    echo -e "  ${GREEN}✓${NC} Network Configuration"
    
    if [[ "${ENABLE_WEB_DASHBOARD}" == "true" ]]; then
        echo -e "  ${GREEN}✓${NC} Web Dashboard"
    else
        echo -e "  ${YELLOW}○${NC} Web Dashboard (skipped)"
    fi
    
    if [[ "${ENABLE_CERTBOT}" == "true" ]]; then
        echo -e "  ${GREEN}✓${NC} Certbot SSL"
    else
        echo -e "  ${YELLOW}○${NC} Certbot SSL (skipped)"
    fi
    
    if [[ "${ENABLE_PENTEST_TOOLS}" == "true" ]]; then    
        echo -e "  ${GREEN}✓${NC} Pentest WiFi Tools (~500MB)"
    else
        echo -e "  ${YELLOW}○${NC} Pentest WiFi Tools (skipped)"
    fi

    if [[ "${ENABLE_HEADLESS_MODE}" == "true" ]]; then
        echo -e "  ${GREEN}✓${NC} Headless Mode (remove GUI, auto-start)"
    else
        echo -e "  ${YELLOW}○${NC} Headless Mode (skipped - GUI kept)"
    fi
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    read -p "Start installation with this configuration? [Y/n]: " -r
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo -e "\n${YELLOW}Installation cancelled.${NC}"
        exit 0
    fi
    
    # Execute installation steps
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              Starting Installation...${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    install_ligolo
    install_web_dashboard
    install_pentest_tools
    install_certbot
    setup_network
    configure_services
    create_management_scripts
    # Headless conversion LAST - after everything is installed
    convert_to_headless
    generate_summary
    
    # Final message
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           ✓ Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "Installation summary: ${BLUE}cat /root/RASPPUNZEL-INFO.txt${NC}"
    echo -e "Installation log: ${BLUE}${INSTALL_LOG}${NC}"
    echo ""
    
    if [[ "${ENABLE_HEADLESS_MODE}" == "true" ]]; then
        echo -e "${YELLOW}⚠️  HEADLESS MODE ENABLED${NC}"
        echo -e "After reboot:"
        echo -e "  - No GUI will be available"
        echo -e "  - System will auto-login to console"
        echo -e "  - All services will start automatically"
        echo -e "  - Access via SSH or web dashboard"
        echo ""
    fi
    
    echo -e "${RED}REBOOT REQUIRED to apply all changes${NC}"
    echo ""
    
    read -p "Reboot now? [Y/n]: " -r
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        log "INFO" "Rebooting system..."
        echo -e "\n${YELLOW}Rebooting in 3 seconds...${NC}"
        sleep 3
        reboot
    else
        echo ""
        echo -e "${GREEN}Installation complete.${NC}"
        echo -e "${YELLOW}Please reboot manually when ready: ${BLUE}sudo reboot${NC}"
        echo ""
    fi
}

# Run main installation
main "$@"