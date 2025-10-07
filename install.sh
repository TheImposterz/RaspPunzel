#!/bin/bash

# =================================================================================================
# RaspPunzel - Lightweight Network Pivot with Ligolo-ng
# =================================================================================================
# Main Installation Script
# =================================================================================================

set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project paths
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"
WEB_DIR="${PROJECT_ROOT}/web"
CONFIG_DIR="${PROJECT_ROOT}/config"

# Installation log
INSTALL_LOG="/var/log/rasppunzel-install.log"

# Banner
print_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              🚀 RaspPunzel Installation 🚀                    ║"
    echo "║                                                               ║"
    echo "║          Lightweight Network Pivot with Ligolo-ng            ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${INSTALL_LOG}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root${NC}" 
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log "ERROR" "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    log "INFO" "Detected OS: ${PRETTY_NAME}"
    
    # Check architecture
    ARCH=$(uname -m)
    log "INFO" "Architecture: ${ARCH}"
    
    if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "armv7l" && "${ARCH}" != "x86_64" ]]; then
        log "ERROR" "Unsupported architecture: ${ARCH}"
        exit 1
    fi
    
    # Check available disk space (minimum 2GB)
    AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
    if [[ ${AVAILABLE_SPACE} -lt 2097152 ]]; then
        log "WARN" "Low disk space detected. At least 2GB recommended."
    fi
    
    log "INFO" "System requirements check passed"
}

# Load configuration
load_config() {
    log "INFO" "Loading configuration..."
    
    if [[ -f "${PROJECT_ROOT}/config.sh" ]]; then
        source "${PROJECT_ROOT}/config.sh"
        log "INFO" "Configuration loaded from config.sh"
    else
        log "WARN" "No config.sh found, using defaults"
    fi
}

# Installation menu
show_menu() {
    echo -e "${BLUE}"
    echo "════════════════════════════════════════════════════════════════"
    echo "  Installation Options"
    echo "════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo "  1) Full Installation (Recommended)"
    echo "     - Ligolo-ng proxy"
    echo "     - Admin WiFi AP"
    echo "     - Web Dashboard"
    echo "     - All network services"
    echo ""
    echo "  2) Minimal Installation"
    echo "     - Ligolo-ng proxy only"
    echo "     - SSH access"
    echo "     - No web dashboard"
    echo ""
    echo "  3) Custom Installation"
    echo "     - Choose components individually"
    echo ""
    echo "  4) Exit"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -n "Select option [1-4]: "
}

# Full installation
full_install() {
    log "INFO" "Starting full installation..."
    
    # Step 1: Install Ligolo-ng
    echo -e "\n${YELLOW}[~] Installing Ligolo-ng...${NC}"
    bash "${SCRIPTS_DIR}/install-ligolo.sh" || {
        log "ERROR" "Ligolo-ng installation failed"
        exit 1
    }
    
    # Step 2: Setup network
    echo -e "\n${YELLOW}[~] Configuring network...${NC}"
    bash "${SCRIPTS_DIR}/setup-network.sh" || {
        log "ERROR" "Network setup failed"
        exit 1
    }
    
    # Step 3: Install web dashboard
    echo -e "\n${YELLOW}[~] Installing web dashboard...${NC}"
    bash "${SCRIPTS_DIR}/install-web-dashboard.sh" || {
        log "ERROR" "Web dashboard installation failed"
        exit 1
    }
    
    # Step 4: Configure services
    echo -e "\n${YELLOW}[~] Configuring services...${NC}"
    bash "${SCRIPTS_DIR}/service-manager.sh" setup || {
        log "ERROR" "Service configuration failed"
        exit 1
    }
    
    log "INFO" "Full installation completed successfully"
}

# Minimal installation
minimal_install() {
    log "INFO" "Starting minimal installation..."
    
    # Only install Ligolo-ng
    echo -e "\n${YELLOW}[~] Installing Ligolo-ng...${NC}"
    bash "${SCRIPTS_DIR}/install-ligolo.sh" minimal || {
        log "ERROR" "Ligolo-ng installation failed"
        exit 1
    }
    
    log "INFO" "Minimal installation completed successfully"
}

# Custom installation
custom_install() {
    log "INFO" "Starting custom installation..."
    
    echo -e "\n${BLUE}Select components to install:${NC}"
    echo ""
    
    read -p "Install Ligolo-ng? [Y/n]: " install_ligolo
    read -p "Install Admin WiFi AP? [Y/n]: " install_ap
    read -p "Install Web Dashboard? [Y/n]: " install_web
    
    # Install Ligolo-ng
    if [[ ! "${install_ligolo}" =~ ^[Nn]$ ]]; then
        echo -e "\n${YELLOW}[~] Installing Ligolo-ng...${NC}"
        bash "${SCRIPTS_DIR}/install-ligolo.sh" || exit 1
    fi
    
    # Install AP
    if [[ ! "${install_ap}" =~ ^[Nn]$ ]]; then
        echo -e "\n${YELLOW}[~] Setting up Admin AP...${NC}"
        bash "${SCRIPTS_DIR}/setup-network.sh" ap-only || exit 1
    fi
    
    # Install web dashboard
    if [[ ! "${install_web}" =~ ^[Nn]$ ]]; then
        echo -e "\n${YELLOW}[~] Installing web dashboard...${NC}"
        bash "${SCRIPTS_DIR}/install-web-dashboard.sh" || exit 1
    fi
    
    log "INFO" "Custom installation completed"
}

# Post-installation
post_install() {
    log "INFO" "Running post-installation tasks..."
    
    # Create management scripts links
    ln -sf "${SCRIPTS_DIR}/start-services.sh" /usr/local/bin/rasppunzel-start
    ln -sf "${SCRIPTS_DIR}/stop-services.sh" /usr/local/bin/rasppunzel-stop
    ln -sf "${SCRIPTS_DIR}/service-manager.sh" /usr/local/bin/rasppunzel-manager
    
    # Set proper permissions
    chmod +x "${SCRIPTS_DIR}"/*.sh
    chmod +x /usr/local/bin/rasppunzel-*
    
    # Create documentation directory
    mkdir -p /opt/rasppunzel/docs
    cp "${PROJECT_ROOT}/README.md" /opt/rasppunzel/docs/ 2>/dev/null || true
    
    # Generate summary
    generate_summary
    
    log "INFO" "Post-installation completed"
}

# Generate installation summary
generate_summary() {
    local SUMMARY_FILE="/root/RASPPUNZEL-INFO.txt"
    
    cat > "${SUMMARY_FILE}" <<EOF
═══════════════════════════════════════════════════════════════
                RaspPunzel Installation Summary
═══════════════════════════════════════════════════════════════

Installation Date: $(date '+%Y-%m-%d %H:%M:%S')
Hostname: $(hostname)
IP Addresses: $(hostname -I)

QUICK START COMMANDS:
  rasppunzel-start        Start all services
  rasppunzel-stop         Stop all services
  rasppunzel-manager      Interactive management menu

LIGOLO-NG:
  Proxy Port: 11601
  TUN Interface: ligolo
  Status: systemctl status ligolo-proxy

ADMIN ACCESS POINT:
  SSID: ${ADMIN_AP_SSID:-PIVOT_ADMIN}
  Password: ${ADMIN_AP_PASSPHRASE:-Check config}
  IP: ${ADMIN_AP_IP:-10.0.0.1}

WEB DASHBOARD:
  URL: http://$(hostname -I | awk '{print $1}'):5000
  Credentials: Check /opt/rasppunzel/web/.credentials

IMPORTANT FILES:
  Install Log: ${INSTALL_LOG}
  Config: ${PROJECT_ROOT}/config.sh
  Scripts: ${SCRIPTS_DIR}

DOCUMENTATION:
  Main: cat /opt/rasppunzel/docs/README.md
  This file: cat ${SUMMARY_FILE}

NEXT STEPS:
  1. Review configuration: nano ${PROJECT_ROOT}/config.sh
  2. Start services: rasppunzel-start
  3. Check status: rasppunzel-manager status
  4. Access web dashboard or connect agent

═══════════════════════════════════════════════════════════════
EOF

    log "INFO" "Installation summary created at ${SUMMARY_FILE}"
}

# Main installation flow
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
    
    # Show menu
    while true; do
        show_menu
        read choice
        
        case $choice in
            1)
                echo -e "\n${GREEN}Starting full installation...${NC}\n"
                full_install
                break
                ;;
            2)
                echo -e "\n${GREEN}Starting minimal installation...${NC}\n"
                minimal_install
                break
                ;;
            3)
                custom_install
                break
                ;;
            4)
                echo -e "\n${YELLOW}Installation cancelled.${NC}"
                exit 0
                ;;
            *)
                echo -e "\n${RED}Invalid option. Please try again.${NC}\n"
                sleep 2
                ;;
        esac
    done
    
    # Post-installation
    post_install
    
    # Final message
    echo -e "\n${GREEN}"
    echo "═══════════════════════════════════════════════════════════════"
    echo "           ✓ RaspPunzel Installation Complete!"
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "Installation summary: ${BLUE}/root/RASPPUNZEL-INFO.txt${NC}"
    echo -e "Installation log: ${BLUE}${INSTALL_LOG}${NC}"
    echo ""
    echo -e "${YELLOW}Reboot recommended to apply all changes.${NC}"
    echo ""
    read -p "Reboot now? [y/N]: " reboot_now
    
    if [[ "${reboot_now}" =~ ^[Yy]$ ]]; then
        log "INFO" "Rebooting system..."
        reboot
    else
        echo -e "\n${GREEN}Please reboot manually when ready: sudo reboot${NC}\n"
    fi
}

# Run main installation
main "$@"