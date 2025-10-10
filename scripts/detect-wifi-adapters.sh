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
        vendor_product=""
        
        if [[ -d "$iface/device" ]]; then
            # Try USB first
            usb_path=$(readlink -f "$iface/device" 2>/dev/null | grep -o "usb[0-9]*/[^/]*" || echo "")
            if [[ -n "$usb_path" ]]; then
                vendor_id=$(cat "$iface/device/../../idVendor" 2>/dev/null || echo "")
                product_id=$(cat "$iface/device/../../idProduct" 2>/dev/null || echo "")
                if [[ -n "$vendor_id" && -n "$product_id" ]]; then
                    vendor_product="${vendor_id}:${product_id}"
                    chipset=$(lsusb -d "$vendor_id:$product_id" 2>/dev/null | cut -d':' -f3- | xargs || echo "USB WiFi")
                fi
            else
                # Try PCI
                pci_path=$(readlink -f "$iface/device" 2>/dev/null | grep -o "[0-9a-f]*:[0-9a-f]*:[0-9a-f]*\.[0-9]" || echo "")
                if [[ -n "$pci_path" ]]; then
                    chipset=$(lspci -s "$pci_path" 2>/dev/null | cut -d':' -f3- | xargs || echo "PCI WiFi")
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
        
        # Check current status
        status="down"
        if [[ -e "$iface/operstate" ]]; then
            operstate=$(cat "$iface/operstate" 2>/dev/null || echo "down")
            if [[ "$operstate" == "up" ]]; then
                status="up"
            fi
        fi
        
        # Store info
        INTERFACE_INFO+=("$iface_name|$mac|$driver|$chipset|$type|$status|$vendor_product")
    fi
done

# =================================================================================================
# Display detected interfaces
# =================================================================================================

if [[ ${#WIRELESS_INTERFACES[@]} -eq 0 ]]; then
    echo -e "${RED}[!] No wireless interfaces detected${NC}"
    echo ""
    echo -e "${YELLOW}Tip: Check if WiFi adapters are properly connected:${NC}"
    echo "  lsusb | grep -i wireless"
    echo "  lsusb | grep -i ralink"
    echo ""
    exit 1
fi

echo -e "${GREEN}Found ${#WIRELESS_INTERFACES[@]} wireless interface(s):${NC}"
echo ""

index=1
for info in "${INTERFACE_INFO[@]}"; do
    IFS='|' read -r iface mac driver chipset type status vendor_product <<< "$info"
    
    echo -e "${BLUE}[$index] ${iface}${NC} (${status})"
    echo -e "    MAC:     ${mac}"
    echo -e "    Driver:  ${driver}"
    echo -e "    Chipset: ${chipset}"
    echo -e "    Type:    ${type}"
    if [[ -n "$vendor_product" && "$vendor_product" != ":" ]]; then
        echo -e "    USB ID:  ${vendor_product}"
    fi
    
    # Check AP mode support
    if command -v iw &>/dev/null; then
        if iw phy 2>/dev/null | grep -A 20 "$iface" | grep -q "* AP"; then
            echo -e "    ${GREEN}✓ Supports AP mode${NC}"
        else
            echo -e "    ${YELLOW}✗ AP mode unknown${NC}"
        fi
    fi
    
    echo ""
    ((index++))
done

# =================================================================================================
# Display USB devices for reference
# =================================================================================================

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           USB WiFi Devices${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

if command -v lsusb &>/dev/null; then
    echo -e "${YELLOW}Connected USB devices:${NC}"
    lsusb | grep -iE 'wireless|wifi|802\.11|ralink|realtek|atheros|mediatek|tp-link|alfa' || echo "  No WiFi USB devices with known keywords"
    echo ""
fi

# =================================================================================================
# Identify best adapters for different uses
# =================================================================================================

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           Adapter Recommendations${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

BUILTIN_IFACE=""
RALINK_INTERFACES=()
OTHER_INTERFACES=()

for info in "${INTERFACE_INFO[@]}"; do
    IFS='|' read -r iface mac driver chipset type status vendor_product <<< "$info"
    
    # Identify built-in (should not be used for AP)
    if [[ "$type" == "built-in" ]]; then
        BUILTIN_IFACE="$iface"
    # Identify Ralink/MediaTek (best for AP)
    elif [[ "$driver" =~ rt.*usb ]] || [[ "$driver" =~ mt76 ]] || [[ "$chipset" =~ [Rr]alink ]] || [[ "$chipset" =~ [Mm]edia[Tt]ek ]]; then
        RALINK_INTERFACES+=("$iface|$mac|$driver|$chipset")
    # Other adapters
    else
        OTHER_INTERFACES+=("$iface|$mac|$driver|$chipset")
    fi
done

# Display built-in WiFi
if [[ -n "$BUILTIN_IFACE" ]]; then
    for info in "${INTERFACE_INFO[@]}"; do
        IFS='|' read -r iface mac driver chipset type status vendor_product <<< "$info"
        if [[ "$iface" == "$BUILTIN_IFACE" ]]; then
            echo -e "${YELLOW}Built-in WiFi:${NC} $iface"
            echo -e "  Chipset: $chipset"
            echo -e "  MAC: $mac"
            echo -e "  ${GREEN}→ Recommended for: Internet connectivity${NC}"
            echo -e "  ${YELLOW}→ Keep managed by NetworkManager${NC}"
            echo ""
        fi
    done
fi

# Display Ralink/MediaTek adapters (best for AP)
if [[ ${#RALINK_INTERFACES[@]} -gt 0 ]]; then
    echo -e "${GREEN}Ralink/MediaTek adapters (excellent for AP):${NC}"
    echo ""
    
    ap_index=1
    for info in "${RALINK_INTERFACES[@]}"; do
        IFS='|' read -r iface mac driver chipset <<< "$info"
        
        if [[ $ap_index -eq 1 ]]; then
            echo -e "  ${GREEN}✓${NC} ${BLUE}$iface${NC} - ${chipset}"
            echo -e "    MAC: $mac"
            echo -e "    Driver: $driver"
            echo -e "    ${GREEN}→ RECOMMENDED FOR ADMIN AP${NC}"
            echo ""
        elif [[ $ap_index -eq 2 ]]; then
            echo -e "  ${GREEN}✓${NC} ${BLUE}$iface${NC} - ${chipset}"
            echo -e "    MAC: $mac"
            echo -e "    Driver: $driver"
            echo -e "    ${YELLOW}→ Available for pentest adapter${NC}"
            echo ""
        else
            echo -e "  ${GREEN}✓${NC} $iface - ${chipset}"
            echo -e "    MAC: $mac"
            echo ""
        fi
        
        ((ap_index++))
    done
fi

# Display other adapters
if [[ ${#OTHER_INTERFACES[@]} -gt 0 ]]; then
    echo -e "${YELLOW}Other WiFi adapters:${NC}"
    echo ""
    
    for info in "${OTHER_INTERFACES[@]}"; do
        IFS='|' read -r iface mac driver chipset <<< "$info"
        echo -e "  ${YELLOW}○${NC} $iface - ${chipset}"
        echo -e "    Driver: $driver"
        echo -e "    ${YELLOW}→ May work for AP (test required)${NC}"
        echo ""
    done
fi

# =================================================================================================
# Generate config.sh snippet
# =================================================================================================

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           Configuration Snippet${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}Would you like to generate config.sh snippet? [Y/n]${NC}"
read -r response

if [[ ! $response =~ ^[Nn]$ ]]; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Copy this to your config.sh:${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "# =============================================="
    echo "# WiFi Interfaces - Auto-detected $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# =============================================="
    echo ""
    
    # Built-in WiFi
    if [[ -n "$BUILTIN_IFACE" ]]; then
        for info in "${INTERFACE_INFO[@]}"; do
            IFS='|' read -r iface mac driver chipset type status vendor_product <<< "$info"
            if [[ "$iface" == "$BUILTIN_IFACE" ]]; then
                echo "# Built-in WiFi (for internet connectivity)"
                echo "MAC_WLAN0=\"${mac}\""
                echo ""
            fi
        done
    fi
    
    # Admin AP - First Ralink adapter
    if [[ ${#RALINK_INTERFACES[@]} -gt 0 ]]; then
        IFS='|' read -r iface mac driver chipset <<< "${RALINK_INTERFACES[0]}"
        echo "# Admin Access Point - Primary adapter"
        echo "# ${chipset}"
        echo "WLAN_INTERFACE_ADMIN=\"${iface}\""
        echo "MAC_WLAN_ADMIN=\"${mac}\"  # Driver: ${driver}"
        echo ""
    fi
    
    # Pentest adapter - Second Ralink adapter
    if [[ ${#RALINK_INTERFACES[@]} -gt 1 ]]; then
        IFS='|' read -r iface mac driver chipset <<< "${RALINK_INTERFACES[1]}"
        echo "# Pentest WiFi Adapter - Secondary adapter"
        echo "# ${chipset}"
        echo "WLAN_INTERFACE_PENTEST=\"${iface}\""
        echo "MAC_WLAN_PENTEST=\"${mac}\"  # Driver: ${driver}"
        echo ""
    fi
    
    # Legacy/other adapters
    if [[ ${#OTHER_INTERFACES[@]} -gt 0 ]]; then
        echo "# Other WiFi adapters (if needed)"
        for info in "${OTHER_INTERFACES[@]}"; do
            IFS='|' read -r iface mac driver chipset <<< "$info"
            echo "# ${iface}: ${chipset}"
            echo "# WLAN_INTERFACE_OTHER=\"${iface}\""
            echo "# MAC_WLAN_OTHER=\"${mac}\""
        done
        echo ""
    fi
    
    echo "# =============================================="
    echo ""
fi

# =================================================================================================
# Summary and next steps
# =================================================================================================

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           Next Steps${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${YELLOW}1.${NC} Copy the configuration snippet above to ${BLUE}config.sh${NC}"
echo -e "${YELLOW}2.${NC} Edit config.sh and customize:"
echo "   - ADMIN_AP_SSID"
echo "   - ADMIN_AP_PASSPHRASE"
echo "   - WIFI_SSID (for internet)"
echo "   - WIFI_PASSPHRASE"
echo ""
echo -e "${YELLOW}3.${NC} Run the installation:"
echo "   ${BLUE}sudo ./install.sh${NC}"
echo ""

if [[ ${#RALINK_INTERFACES[@]} -eq 0 ]]; then
    echo -e "${RED}⚠ WARNING:${NC} No Ralink/MediaTek adapters detected!"
    echo "  Admin AP may not work properly with other chipsets."
    echo "  Consider using a Ralink RT5370 or MT7601U adapter."
    echo ""
fi

echo -e "${GREEN}Detection complete!${NC}"
echo ""