#!/bin/bash
# =================================================================================================
# FILE: scripts/start-services.sh
# =================================================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

echo -e "${YELLOW}[~] Starting RaspPunzel services...${NC}"
echo ""

# Start Ligolo Proxy
echo -n "Starting Ligolo Proxy... "
if systemctl start ligolo-proxy 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Start Hostapd (Admin AP)
echo -n "Starting Admin AP... "
if systemctl start hostapd 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Start Dnsmasq
echo -n "Starting DHCP/DNS... "
if systemctl start dnsmasq 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Start SSH (if not already running)
if ! systemctl is-active --quiet ssh; then
    echo -n "Starting SSH... "
    if systemctl start ssh 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
fi

# Start Web Dashboard (if enabled)
if systemctl list-unit-files | grep -q rasppunzel-web; then
    echo -n "Starting Web Dashboard... "
    if systemctl start rasppunzel-web 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
fi

echo ""
echo -e "${GREEN}[+] Services started${NC}"
echo ""
echo -e "${YELLOW}Check status with: rasppunzel-manager status${NC}"
echo ""
