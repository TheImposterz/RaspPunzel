#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

echo -e "${YELLOW}[~] Stopping RaspPunzel services...${NC}"
echo ""

# Stop Ligolo Proxy
echo -n "Stopping Ligolo Proxy... "
if systemctl stop ligolo-proxy 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Stop Hostapd
echo -n "Stopping Admin AP... "
if systemctl stop hostapd 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Stop Dnsmasq
echo -n "Stopping DHCP/DNS... "
if systemctl stop dnsmasq 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# Stop Web Dashboard
if systemctl list-unit-files | grep -q rasppunzel-web; then
    echo -n "Stopping Web Dashboard... "
    if systemctl stop rasppunzel-web 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
fi

echo ""
echo -e "${GREEN}[+] Services stopped${NC}"
echo ""