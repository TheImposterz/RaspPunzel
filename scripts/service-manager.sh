#!/bin/bash

# =================================================================================================
# RaspPunzel - Service Manager
# =================================================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Services to manage
SERVICES=("ligolo-proxy" "hostapd" "dnsmasq" "ssh")

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

# Show status of all services
show_status() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  RaspPunzel Service Status${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "  ${GREEN}[✓] $service: RUNNING${NC}"
        else
            echo -e "  ${RED}[✗] $service: STOPPED${NC}"
        fi
    done
    
    echo ""
    echo -e "${YELLOW}Network Interfaces:${NC}"
    ip -brief addr show | grep -v "lo"
    
    echo ""
    echo -e "${YELLOW}Active Connections:${NC}"
    echo "Ligolo Proxy:"
    ss -tulpn 2>/dev/null | grep ":11601" || echo "  Not listening"
    
    echo ""
}

# Start all services
start_all() {
    echo -e "${YELLOW}[~] Starting all services...${NC}"
    
    for service in "${SERVICES[@]}"; do
        echo -n "  Starting $service... "
        if systemctl start "$service" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Services start command completed${NC}"
}

# Stop all services
stop_all() {
    echo -e "${YELLOW}[~] Stopping all services...${NC}"
    
    for service in "${SERVICES[@]}"; do
        echo -n "  Stopping $service... "
        if systemctl stop "$service" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Services stop command completed${NC}"
}

# Restart all services
restart_all() {
    echo -e "${YELLOW}[~] Restarting all services...${NC}"
    
    for service in "${SERVICES[@]}"; do
        echo -n "  Restarting $service... "
        if systemctl restart "$service" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    done
    
    echo -e "${GREEN}[+] Services restart command completed${NC}"
}

# View logs
view_logs() {
    echo -e "${YELLOW}Select service to view logs:${NC}"
    echo "  1) Ligolo Proxy"
    echo "  2) Hostapd (Admin AP)"
    echo "  3) Dnsmasq (DHCP/DNS)"
    echo "  4) SSH"
    echo "  5) All services"
    echo ""
    read -p "Choice [1-5]: " choice
    
    case $choice in
        1) journalctl -u ligolo-proxy -n 50 --no-pager ;;
        2) journalctl -u hostapd -n 50 --no-pager ;;
        3) journalctl -u dnsmasq -n 50 --no-pager ;;
        4) journalctl -u ssh -n 50 --no-pager ;;
        5) 
            for service in "${SERVICES[@]}"; do
                echo -e "\n${BLUE}=== $service ===${NC}"
                journalctl -u "$service" -n 20 --no-pager
            done
            ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
}

# Show network information
show_network() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Network Information${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${YELLOW}Interfaces:${NC}"
    ip addr show
    
    echo ""
    echo -e "${YELLOW}Routes:${NC}"
    ip route show
    
    echo ""
    echo -e "${YELLOW}Listening Ports:${NC}"
    ss -tulpn | grep -E "(ligolo|hostapd|dnsmasq|ssh)"
    
    echo ""
    echo -e "${YELLOW}Connected Clients (DHCP):${NC}"
    if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
        cat /var/lib/misc/dnsmasq.leases
    else
        echo "  No DHCP leases"
    fi
    
    echo ""
}

# Interactive menu
show_menu() {
    while true; do
        clear
        echo -e "${GREEN}"
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║                                                               ║"
        echo "║              RaspPunzel Service Manager                       ║"
        echo "║                                                               ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        echo "  1) Show Status"
        echo "  2) Start All Services"
        echo "  3) Stop All Services"
        echo "  4) Restart All Services"
        echo "  5) View Logs"
        echo "  6) Network Information"
        echo "  7) Restart Ligolo Proxy Only"
        echo "  8) Exit"
        echo ""
        read -p "Select option [1-8]: " choice
        
        case $choice in
            1)
                show_status
                read -p "Press Enter to continue..."
                ;;
            2)
                start_all
                read -p "Press Enter to continue..."
                ;;
            3)
                stop_all
                read -p "Press Enter to continue..."
                ;;
            4)
                restart_all
                read -p "Press Enter to continue..."
                ;;
            5)
                view_logs
                read -p "Press Enter to continue..."
                ;;
            6)
                show_network
                read -p "Press Enter to continue..."
                ;;
            7)
                echo -e "${YELLOW}[~] Restarting Ligolo Proxy...${NC}"
                systemctl restart ligolo-proxy
                echo -e "${GREEN}[+] Ligolo Proxy restarted${NC}"
                read -p "Press Enter to continue..."
                ;;
            8)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                sleep 2
                ;;
        esac
    done
}

# Main script logic
case "${1:-menu}" in
    status)
        show_status
        ;;
    start)
        start_all
        ;;
    stop)
        stop_all
        ;;
    restart)
        restart_all
        ;;
    logs)
        view_logs
        ;;
    network)
        show_network
        ;;
    setup)
        # Called during installation
        echo -e "${GREEN}[+] Service manager configured${NC}"
        ;;
    menu|*)
        show_menu
        ;;
esac