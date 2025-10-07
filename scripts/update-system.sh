#!/bin/bash

# =================================================================================================
# RaspPunzel - System Update Script
# =================================================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  RaspPunzel System Update${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Update system packages
update_system() {
    echo -e "${YELLOW}[~] Updating system packages...${NC}"
    apt-get update
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get autoclean
    echo -e "${GREEN}[+] System packages updated${NC}"
}

# Update Ligolo-ng
update_ligolo() {
    echo -e "${YELLOW}[~] Checking for Ligolo-ng updates...${NC}"
    
    # Get current version
    if [[ -f /opt/ligolo-ng/VERSION ]]; then
        CURRENT_VERSION=$(cat /opt/ligolo-ng/VERSION)
        echo "  Current version: ${CURRENT_VERSION}"
    else
        CURRENT_VERSION="unknown"
        echo "  Current version: Unknown"
    fi
    
    # Get latest version
    LATEST_VERSION=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -z "$LATEST_VERSION" ]]; then
        echo -e "${RED}[!] Could not fetch latest version${NC}"
        return 1
    fi
    
    echo "  Latest version: ${LATEST_VERSION}"
    
    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
        echo -e "${GREEN}[+] Ligolo-ng is already up to date!${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}[~] Updating from ${CURRENT_VERSION} to ${LATEST_VERSION}...${NC}"
    
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64) LIGOLO_ARCH="arm64" ;;
        armv7l) LIGOLO_ARCH="armv7" ;;
        x86_64) LIGOLO_ARCH="amd64" ;;
        *) echo -e "${RED}Unsupported architecture${NC}"; return 1 ;;
    esac
    
    # Stop service
    systemctl stop ligolo-proxy
    
    # Backup current version
    cp /opt/ligolo-ng/proxy /opt/ligolo-ng/proxy.backup
    
    # Download new version
    cd /tmp
    wget -q "https://github.com/nicocha30/ligolo-ng/releases/download/${LATEST_VERSION}/ligolo-ng_proxy_${LATEST_VERSION}_linux_${LIGOLO_ARCH}.tar.gz"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[!] Download failed${NC}"
        systemctl start ligolo-proxy
        return 1
    fi
    
    # Extract and install
    tar -xzf "ligolo-ng_proxy_${LATEST_VERSION}_linux_${LIGOLO_ARCH}.tar.gz"
    mv proxy /opt/ligolo-ng/
    chmod +x /opt/ligolo-ng/proxy
    
    # Save version
    echo "${LATEST_VERSION}" > /opt/ligolo-ng/VERSION
    
    # Cleanup
    rm -f /tmp/ligolo-ng_*.tar.gz
    
    # Restart service
    systemctl start ligolo-proxy
    
    echo -e "${GREEN}[+] Ligolo-ng updated to ${LATEST_VERSION}${NC}"
    echo "  Backup saved: /opt/ligolo-ng/proxy.backup"
}

# Menu
if [[ $# -eq 0 ]]; then
    echo "Select update option:"
    echo "  1) Update system packages"
    echo "  2) Update Ligolo-ng"
    echo "  3) Update both"
    echo "  4) Exit"
    echo ""
    read -p "Choice [1-4]: " choice
    
    case $choice in
        1)
            update_system
            ;;
        2)
            update_ligolo
            ;;
        3)
            update_system
            echo ""
            update_ligolo
            ;;
        4)
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            exit 1
            ;;
    esac
else
    # Command line argument
    case "$1" in
        system)
            update_system
            ;;
        ligolo)
            update_ligolo
            ;;
        full|all)
            update_system
            echo ""
            update_ligolo
            ;;
        *)
            echo "Usage: $0 [system|ligolo|full]"
            exit 1
            ;;
    esac
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Update Complete${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""