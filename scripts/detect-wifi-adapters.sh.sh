#!/bin/bash
# =================================================================================================
# RaspPunzel - WiFi Adapters Detection Script
# =================================================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           WiFi Adapters Detection${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# =================================================================================================
# Detect all wireless interfaces
# =================================================================================================

echo -e "${YELLOW}[~] Detecting wireless interfaces...${NC}"
echo ""

WIRELESS_INTERFACES=()
INTERFACE_INFO=()

for iface in /sys/class/net/*; do
    iface_name=$(basename "$iface")
    
    # Check if it's a wireless interface
    if [[ -d "$iface/wireless" ]] || [[ -L "$iface/phy80211" ]]; then
        WIRELESS_INTERFACES+=("$iface_name")
        
        # Get MAC address
        mac=$(cat "$iface/address" 2>/dev/null || echo "unknown")
        
        # Get driver
        if [[ -L "$iface/device/driver" ]]; then
            driver=$(basename "$(readlink "$iface/device/driver")")
        else
            driver="unknown"
        fi
        
        # Get chipset/model via lsusb or lspci
        chipset="unknown"
        if [[ -d "$iface/device" ]]; then
            # Try USB first
            usb_path=$(readlink -f "$iface/device" | grep -o "usb[0-9]*/[^/]*")
            if [[ -n "$usb_path" ]]; then
                vendor_id=$(cat "$iface/device/../../idVendor" 2>/dev/null || echo "")
                product_id=$(cat "$iface/device/../../idProduct" 2>/dev/null || echo "")
                if [[ -n "$vendor_id" && -n "$product_id" ]]; then
                    chipset=$(lsusb -d "$vendor_id:$product_id" | cut -d':' -f3- | xargs)
                fi
            else
                # Try PCI
                pci_path=$(readlink -f "$iface/device" | grep -o "[0-9a-f]*:[0-9a-f]*:[0-9a-f]*\.[0-9]")
                if [[ -n "$pci_path" ]]; then
                    chipset=$(lspci -s "$pci_path" | cut -d':' -f3- | xargs)
                fi
            fi
        fi
        
        # Determine if built-in or USB
        type="unknown"
        if [[ "$iface_name" == "wlan0" ]]; then
            type="built-in"
        elif [[ "$iface_name" =~ ^wlx ]]; then
            type="USB (MAC-based name)"
        elif [[ "$iface_name" =~ ^wlan[1-9] ]]; then
            type="USB"
        fi
        
        # Store info
        INTERFACE_INFO+=("$iface_name|$mac|$driver|$chipset|$type")
    fi
done

# =================================================================================================
# Display detected interfaces
# =================================================================================================

if [[ ${#WIRELESS_INTERFACES[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No wireless interfaces detected${NC}"
    exit 1
fi

echo -e "${GREEN}Found ${#WIRELESS_INTERFACES[@]} wireless interface(s):${NC}"
echo ""

index=1
for info in "${INTERFACE_INFO[@]}"; do
    IFS='|' read -r iface mac driver chipset type <<< "$info"
    
    echo -e "${BLUE}[$index] ${iface}${NC}"
    echo -e "    MAC:     ${mac}"
    echo -e "    Driver:  ${driver}"
    echo -e "    Chipset: ${chipset}"
    echo -e "    Type:    ${type}"
    echo ""
    
    ((index++))
done

# =================================================================================================
# Identify Ralink adapters
# =================================================================================================

echo -e "${YELLOW}[~] Identifying Ralink adapters...${NC}"
echo ""

RALINK_INTERFACES=()

for info in "${INTERFACE_INFO[@]}"; do
    IFS='|' read -r iface mac driver chipset type <<< "$info"
    
    # Check if Ralink
    if [[ "$driver" =~ rt.*usb ]] || [[ "$chipset" =~ [Rr]alink ]]; then
        RALINK_INTERFACES+=("$iface")
        echo -e "  ${GREEN}✓${NC} $iface - Ralink adapter (Good for AP)"
    fi
done

if [[ ${#RALINK_INTERFACES[@]} -eq 0 ]]; then
    echo -e "${YELLOW}[~] No Ralink adapters found${NC}"
    echo -e "${YELLOW}[~] Will check for other suitable adapters...${NC}"
    echo ""
    
    # Look for other common AP-capable chipsets
    for info in "${INTERFACE_INFO[@]}"; do
        IFS='|' read -r iface mac driver chipset type <<< "$info"
        
        if [[ "$driver" =~ rtl88 ]] || [[ "$driver" =~ ath9k ]] || [[ "$driver" =~ mt76 ]]; then
            echo -e "  ${YELLOW}○${NC} $iface - ${driver} (May work for AP)"
        fi
    done
fi

# =================================================================================================
# Recommendations
# =================================================================================================

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           Recommendations${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Identify built-in (should not be used for AP)
BUILTIN_IFACE=""
for info in "${INTERFACE_INFO[@]}"; do
    IFS='|' read -r iface mac driver chipset type <<< "$info"
    if [[ "$type" == "built-in" ]]; then
        BUILTIN_IFACE="$iface"
        echo -e "${YELLOW}Built-in WiFi:${NC} $iface ($chipset)"
        echo -e "  → Keep for internet connectivity"
        echo ""
    fi
done

# Recommend adapter for AP
if [[ ${#RALINK_INTERFACES[@]} -gt 0 ]]; then
    RECOMMENDED_AP="${RALINK_INTERFACES[0]}"
    
    echo -e "${GREEN}Recommended for Admin AP:${NC} ${RECOMMENDED_AP}"
    
    # Get MAC for config
    for info in "${INTERFACE_INFO[@]}"; do
        IFS='|' read -r iface mac driver chipset type <<< "$info"
        if [[ "$iface" == "$RECOMMENDED_AP" ]]; then
            echo -e "  Interface: ${RECOMMENDED_AP}"
            echo -e "  MAC: ${mac}"
            echo -e "  Driver: ${driver}"
            echo ""
            
            echo -e "${YELLOW}Add to config.sh:${NC}"
            echo -e "  ${BLUE}WLAN_INTERFACE_ADMIN=\"${RECOMMENDED_AP}\"${NC}"
            echo -e "  ${BLUE}MAC_WLAN_ADMIN=\"${mac}\"${NC}"
        fi
    done
    
    # If there's a second Ralink
    if [[ ${#RALINK_INTERFACES[@]} -gt 1 ]]; then
        RECOMMENDED_PENTEST="${RALINK_INTERFACES[1]}"
        echo ""
        echo -e "${GREEN}Available for pentest:${NC} ${RECOMMENDED_PENTEST}"
        
        for info in "${INTERFACE_INFO[@]}"; do
            IFS='|' read -r iface mac driver chipset type <<< "$info"
            if [[ "$iface" == "$RECOMMENDED_PENTEST" ]]; then
                echo -e "  ${BLUE}WLAN_INTERFACE_PENTEST=\"${RECOMMENDED_PENTEST}\"${NC}"
                echo -e "  ${BLUE}MAC_WLAN_PENTEST=\"${mac}\"${NC}"
            fi
        done
    fi
else
    echo -e "${RED}[!] No Ralink adapters found for AP${NC}"
    echo -e "${YELLOW}[~] You may try with other adapters, but AP mode may not work${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# =================================================================================================
# Auto-generate config snippet
# =================================================================================================

echo -e "${YELLOW}Would you like to auto-generate config.sh snippet? [Y/n]${NC}"
read -r response

if [[ ! $response =~ ^[Nn]$ ]]; then
    echo ""
    echo -e "${GREEN}Copy this to your config.sh:${NC}"
    echo ""
    echo "# =============================================="
    echo "# WiFi Interfaces - Auto-detected"
    echo "# =============================================="
    echo ""
    
    # Built-in
    if [[ -n "$BUILTIN_IFACE" ]]; then
        for info in "${INTERFACE_INFO[@]}"; do
            IFS='|' read -r iface mac driver chipset type <<< "$info"
            if [[ "$iface" == "$BUILTIN_IFACE" ]]; then
                echo "# Built-in WiFi (for internet)"
                echo "MAC_WLAN0=\"${mac}\""
                echo ""
            fi
        done
    fi
    
    # Admin AP
    if [[ -n "$RECOMMENDED_AP" ]]; then
        for info in "${INTERFACE_INFO[@]}"; do
            IFS='|' read -r iface mac driver chipset type <<< "$info"
            if [[ "$iface" == "$RECOMMENDED_AP" ]]; then
                echo "# Admin Access Point (Ralink adapter)"
                echo "WLAN_INTERFACE_ADMIN=\"${RECOMMENDED_AP}\""
                echo "MAC_WLAN_ADMIN=\"${mac}\"  # ${chipset}"
                echo ""
            fi
        done
    fi
    
    # Pentest adapter
    if [[ -n "$RECOMMENDED_PENTEST" ]]; then
        for info in "${INTERFACE_INFO[@]}"; do
            IFS='|' read -r iface mac driver chipset type <<< "$info"
            if [[ "$iface" == "$RECOMMENDED_PENTEST" ]]; then
                echo "# Pentest adapter (available)"
                echo "WLAN_INTERFACE_PENTEST=\"${RECOMMENDED_PENTEST}\""
                echo "MAC_WLAN_PENTEST=\"${mac}\"  # ${chipset}"
                echo ""
            fi
        done
    fi
    
    echo "# =============================================="
fi

echo ""