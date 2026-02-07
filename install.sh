#!/bin/bash
# GRE Master v8.0 - Multi-Tunnel Manager
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
CONFIG_DIR="/etc/gre-tunnels"
LOG_DIR="/var/log/gre-tunnels"
BACKUP_DIR="/etc/gre-tunnels/backups"

# Create directories
mkdir -p $CONFIG_DIR $LOG_DIR $BACKUP_DIR

draw_header() {
    clear
    echo -e "${PURPLE}"
    echo "    ╔═════════════════════════════╗"
    echo "    ║    ██████╗ ██████╗ ███████╗ ║"
    echo "    ║   ██╔════╝ ██╔══██╗██╔════╝ ║"
    echo "    ║   ██║  ███╗██████╔╝█████╗   ║"
    echo "    ║   ██║   ██║██╔══██╗██╔══╝   ║"
    echo "    ║   ╚██████╔╝██║  ██║███████╗ ║"
    echo "    ║    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ║"
    echo "    ╚═════════════════════════════╝${NC}"
    echo -e "${CYAN}           GRE Tunnel Manager v8.0${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # Show active tunnels count
    ACTIVE_COUNT=$(ip link show 2>/dev/null | grep -c "gre[0-9]")
    echo -e "${YELLOW}Active Tunnels: $ACTIVE_COUNT${NC}"
    echo "${RED} Ghabl az harchizi dar server iran ba gozine 3 ip haye iran ra ezafe konid${NC}"
}

# Function to list all tunnels
list_tunnels() {
    echo -e "${CYAN}[+] Current GRE Tunnels${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # List system tunnels
    echo -e "${YELLOW}System Tunnels:${NC}"
    local tunnel_count=0
    for tunnel in $(ip link show 2>/dev/null | grep "gre[0-9]:" | awk -F: '{print $2}' | tr -d ' '); do
        tunnel_count=$((tunnel_count + 1))
        local local_ip=$(ip addr show $tunnel 2>/dev/null | grep "inet " | awk '{print $2}')
        local remote_ip=$(ip -d link show $tunnel 2>/dev/null | grep -o "remote [0-9.]*" | awk '{print $2}')
        local state=$(ip link show $tunnel 2>/dev/null | grep -o "state [A-Z]*" | awk '{print $2}')
        
        echo -e "${GREEN}  $tunnel_count. $tunnel${NC}"
        echo -e "     Local IP: ${local_ip:-Not configured}"
        echo -e "     Remote IP: ${remote_ip:-Not configured}"
        echo -e "     State: ${state:-DOWN}"
        echo ""
    done
    
    if [ $tunnel_count -eq 0 ]; then
        echo -e "${RED}  No active tunnels found${NC}"
        echo ""
    fi
    
    # List configured tunnel files
    echo -e "${YELLOW}Configured Tunnel Files:${NC}"
    local config_count=0
    for config_file in $CONFIG_DIR/*.conf; do
        config_count=$((config_count + 1))
        local tunnel_name=$(basename "$config_file" .conf)
        local tunnel_dev=$(grep "^TUNNEL_DEV=" "$config_file" 2>/dev/null | cut -d= -f2)
        
        echo -e "${CYAN}  $config_count. $tunnel_name${NC}"
        echo -e "     Config: $config_file"
        echo -e "     Device: ${tunnel_dev:-Not specified}"
        echo ""
    done
    
    if [ $config_count -eq 0 ]; then
        echo -e "${YELLOW}  No tunnel configurations found${NC}"
        echo ""
    fi
    
    read -p "Press Enter to continue..."
}

# Function to show detailed tunnel status
tunnel_status() {
    echo -e "${CYAN}[+] Tunnel Status Dashboard${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # Get all GRE interfaces
    local tunnels=$(ip link show 2>/dev/null | grep "gre[0-9]:" | awk -F: '{print $2}' | tr -d ' ')
    
    if [ -z "$tunnels" ]; then
        echo -e "${RED}No GRE tunnels found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    for tunnel in $tunnels; do
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}Tunnel: $tunnel${NC}"
        
        # Get tunnel details
        local local_ip=$(ip addr show $tunnel 2>/dev/null | grep "inet " | awk '{print $2}')
        local remote_ip=$(ip -d link show $tunnel 2>/dev/null | grep -o "remote [0-9.]*" | awk '{print $2}')
        local local_pub=$(ip -d link show $tunnel 2>/dev/null | grep -o "local [0-9.]*" | awk '{print $2}')
        local state=$(ip link show $tunnel 2>/dev/null | grep -o "state [A-Z]*" | awk '{print $2}')
        local mtu=$(ip link show $tunnel 2>/dev/null | grep -o "mtu [0-9]*" | awk '{print $2}')
        local ttl=$(ip -d link show $tunnel 2>/dev/null | grep -o "ttl [0-9]*" | awk '{print $2}')
        
        echo -e "  State:        ${state:-UNKNOWN}"
        echo -e "  Local IP:     ${local_ip:-Not set}"
        echo -e "  Remote IP:    ${remote_ip:-Not set}"
        echo -e "  Public IP:    ${local_pub:-Not set}"
        echo -e "  MTU:          ${mtu:-1500}"
        echo -e "  TTL:          ${ttl:-64}"
        
        # Check connectivity
        if [ "$state" = "UP" ] && [ -n "$local_ip" ]; then
            local peer_ip=$(echo $local_ip | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3"."$4-1}')
            echo -e "\n  ${YELLOW}Connectivity Test:${NC}"
            
            # Ping test
            if ping -c 2 -W 1 -I $tunnel $peer_ip >/dev/null 2>&1; then
                echo -e "  Ping:          ${GREEN}✓ Reachable${NC}"
            else
                echo -e "  Ping:          ${RED}✗ Unreachable${NC}"
            fi
            
            # Route test
            local routes_count=$(ip route show dev $tunnel 2>/dev/null | wc -l)
            echo -e "  Routes:        $routes_count via this tunnel"
            
            # Traffic stats
            echo -e "\n  ${YELLOW}Traffic Statistics:${NC}"
            local rx_bytes=$(ip -s link show $tunnel 2>/dev/null | grep -A1 "RX:" | tail -1 | awk '{print $1}')
            local tx_bytes=$(ip -s link show $tunnel 2>/dev/null | grep -A1 "TX:" | tail -1 | awk '{print $1}')
            
            if [ -n "$rx_bytes" ]; then
                echo -e "  Received:      $(numfmt --to=iec $rx_bytes)"
                echo -e "  Transmitted:   $(numfmt --to=iec $tx_bytes)"
            fi
        fi
        
        # Check for associated service
        local service_name="gre-${tunnel}.service"
        if systemctl is-active $service_name >/dev/null 2>&1; then
            echo -e "\n  Service:       ${GREEN}✓ $service_name (active)${NC}"
        elif systemctl is-enabled $service_name >/dev/null 2>&1; then
            echo -e "\n  Service:       ${YELLOW}○ $service_name (enabled, not active)${NC}"
        fi
    done
    
    echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}System Information:${NC}"
    echo -e "  IP Forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo -e "  Total GRE interfaces: $(ip link show 2>/dev/null | grep -c "gre[0-9]:")"
    
    read -p "Press Enter to continue..."
}

setup_iran() {
    echo -e "${CYAN}[+] Setting up IRAN Tunnel${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # Get tunnel name
    read -p "Enter tunnel name (e.g., tunnel-1, iran-main): " TUNNEL_NAME
    if [[ -z "$TUNNEL_NAME" ]]; then
        echo -e "${RED}Tunnel name cannot be empty!${NC}"
        sleep 2
        return
    fi
    
    # Check if tunnel name already exists
    if [ -f "$CONFIG_DIR/$TUNNEL_NAME.conf" ]; then
        echo -e "${YELLOW}Tunnel '$TUNNEL_NAME' already exists.${NC}"
        read -p "Overwrite? (y/n): " OVERWRITE
        if [[ "$OVERWRITE" != "y" ]]; then
            return
        fi
    fi
    
    # Get tunnel device name
    read -p "Enter tunnel device name [default: gre1]: " TUNNEL_DEV
    TUNNEL_DEV=${TUNNEL_DEV:-gre1}
    
    # Check if device already exists
    if ip link show $TUNNEL_DEV >/dev/null 2>&1; then
        echo -e "${YELLOW}Device $TUNNEL_DEV already exists.${NC}"
        read -p "Remove existing device? (y/n): " REMOVE_EXISTING
        if [[ "$REMOVE_EXISTING" == "y" ]]; then
            ip link set $TUNNEL_DEV down 2>/dev/null
            ip tunnel del $TUNNEL_DEV 2>/dev/null
        else
            echo -e "${RED}Cannot proceed. Device exists.${NC}"
            sleep 2
            return
        fi
    fi
    
    # Get tunnel configuration
    read -p "Enter Iran Public IP: " IRAN_IP
    read -p "Enter Foreign Public IP: " KHAREJ_IP
    read -p "Enter Iran local IP [default: 10.10.0.2]: " IRAN_LOCAL_IP
    IRAN_LOCAL_IP=${IRAN_LOCAL_IP:-10.10.0.2}
    
    # Calculate network prefix
    TUNNEL_NET=$(echo $IRAN_LOCAL_IP | awk -F. '{print $1"."$2"."$3".0/30"}')
    REMOTE_LOCAL_IP=$(echo $IRAN_LOCAL_IP | awk -F. '{print $1"."$2"."$3".1"}')
    
    # Validate IPs
    for ip in "$IRAN_IP" "$KHAREJ_IP" "$IRAN_LOCAL_IP"; do
        if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid IP address: $ip${NC}"
            sleep 2
            return
        fi
    done
    
    # Get default gateway
    DEFAULT_GW=$(ip route | grep default | awk '{print $3}' | head -n 1)
    
    echo -e "\n${YELLOW}[*] Creating tunnel configuration...${NC}"
    
    # Save configuration
    cat > "$CONFIG_DIR/$TUNNEL_NAME.conf" << EOF
# GRE Tunnel Configuration - $TUNNEL_NAME
TUNNEL_NAME="$TUNNEL_NAME"
TUNNEL_DEV="$TUNNEL_DEV"
TUNNEL_TYPE="iran"
IRAN_PUBLIC_IP="$IRAN_IP"
KHAREJ_PUBLIC_IP="$KHAREJ_IP"
IRAN_LOCAL_IP="$IRAN_LOCAL_IP"
REMOTE_LOCAL_IP="$REMOTE_LOCAL_IP"
TUNNEL_NET="$TUNNEL_NET"
CREATED_DATE="$(date)"
EOF
    
    # Create setup script
    cat > "/usr/local/bin/gre-$TUNNEL_NAME.sh" << EOF
#!/bin/bash
# Setup script for $TUNNEL_NAME

# Load configuration
source $CONFIG_DIR/$TUNNEL_NAME.conf

# Remove existing tunnel
ip link set \$TUNNEL_DEV down 2>/dev/null
ip tunnel del \$TUNNEL_DEV 2>/dev/null

# Create tunnel
ip tunnel add \$TUNNEL_DEV mode gre remote \$KHAREJ_PUBLIC_IP local \$IRAN_PUBLIC_IP ttl 225
ip addr add \$IRAN_LOCAL_IP/30 dev \$TUNNEL_DEV
ip link set \$TUNNEL_DEV up

# Add route for Kharej through default gateway
if [ -n "$DEFAULT_GW" ]; then
    ip route add \$KHAREJ_PUBLIC_IP via $DEFAULT_GW 2>/dev/null
fi

# DNS configuration
chattr -i /etc/resolv.conf 2>/dev/null
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
chattr +i /etc/resolv.conf

# Set default route through tunnel
ip route replace default via \$REMOTE_LOCAL_IP dev \$TUNNEL_DEV 2>/dev/null

# Log the setup
echo "\$(date): Tunnel \$TUNNEL_DEV (\$TUNNEL_NAME) started" >> $LOG_DIR/$TUNNEL_NAME.log
EOF
    
    chmod +x "/usr/local/bin/gre-$TUNNEL_NAME.sh"
    
    # Get custom routes
    echo -e "\n${CYAN}[*] Custom Routing Configuration${NC}"
    echo -e "${YELLOW}Enter custom routes (one per line, format: DESTINATION via GATEWAY)"
    echo -e "Example: 192.168.1.0/24 via $REMOTE_LOCAL_IP"
    echo -e "Leave empty and press Enter when done${NC}"
    
    ROUTES_FILE="$CONFIG_DIR/$TUNNEL_NAME-routes.conf"
    > "$ROUTES_FILE"
    
    while true; do
        read -p "Route: " ROUTE
        if [[ -z "$ROUTE" ]]; then
            break
        fi
        echo "$ROUTE" >> "$ROUTES_FILE"
        echo "ip route add $ROUTE 2>/dev/null || true" >> "/usr/local/bin/gre-$TUNNEL_NAME.sh"
    done
    
    # Create service file
    cat > "/etc/systemd/system/gre-$TUNNEL_NAME.service" << EOF
[Unit]
Description=GRE Tunnel - $TUNNEL_NAME
After=network.target
Wants=network.target
Documentation=file:$CONFIG_DIR/$TUNNEL_NAME.conf

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/gre-$TUNNEL_NAME.sh
ExecStop=/bin/bash -c "ip link set $TUNNEL_DEV down 2>/dev/null; ip tunnel del $TUNNEL_DEV 2>/dev/null; echo \"\$(date): Tunnel stopped\" >> $LOG_DIR/$TUNNEL_NAME.log"
WorkingDirectory=/root
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    
    # Execute setup
    echo -e "\n${YELLOW}[*] Configuring tunnel...${NC}"
    /usr/local/bin/gre-$TUNNEL_NAME.sh
    
    # Enable service
    systemctl daemon-reload
    systemctl enable "gre-$TUNNEL_NAME.service"
    systemctl start "gre-$TUNNEL_NAME.service"
    
    # Configure auto-reboot
    read -p "Enable auto-reboot schedule? (y/n): " ENABLE_REBOOT
    if [[ "$ENABLE_REBOOT" == "y" ]]; then
        read -p "Reboot interval (hours): " REBOOT_HOURS
        if [[ $REBOOT_HOURS =~ ^[0-9]+$ ]] && [[ $REBOOT_HOURS -gt 0 ]]; then
            # Add to crontab with unique comment
            (crontab -l 2>/dev/null | grep -v "#gre-$TUNNEL_NAME#"; echo "0 */$REBOOT_HOURS * * * /sbin/reboot #gre-$TUNNEL_NAME#") | crontab -
            echo -e "${GREEN}[+] Auto-reboot scheduled every $REBOOT_HOURS hours${NC}"
        fi
    fi
    
    echo -e "\n${GREEN}[✓] Iran tunnel '$TUNNEL_NAME' setup complete!${NC}"
    echo -e "${CYAN}"
    echo "  Tunnel Device:    $TUNNEL_DEV"
    echo "  Local IP:         $IRAN_LOCAL_IP"
    echo "  Remote IP:        $KHAREJ_IP"
    echo "  Configuration:    $CONFIG_DIR/$TUNNEL_NAME.conf"
    echo "  Service:          gre-$TUNNEL_NAME.service"
    echo "  Log File:         $LOG_DIR/$TUNNEL_NAME.log"
    echo -e "${NC}"
    
    sleep 3
}

setup_foreign() {
    echo -e "${CYAN}[+] Setting up FOREIGN Tunnel${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # Get tunnel name
    read -p "Enter tunnel name (e.g., foreign-1, gateway-main): " TUNNEL_NAME
    if [[ -z "$TUNNEL_NAME" ]]; then
        echo -e "${RED}Tunnel name cannot be empty!${NC}"
        sleep 2
        return
    fi
    
    # Check if tunnel name already exists
    if [ -f "$CONFIG_DIR/$TUNNEL_NAME.conf" ]; then
        echo -e "${YELLOW}Tunnel '$TUNNEL_NAME' already exists.${NC}"
        read -p "Overwrite? (y/n): " OVERWRITE
        if [[ "$OVERWRITE" != "y" ]]; then
            return
        fi
    fi
    
    # Get tunnel device name
    read -p "Enter tunnel device name [default: gre1]: " TUNNEL_DEV
    TUNNEL_DEV=${TUNNEL_DEV:-gre1}
    
    # Check if device already exists
    if ip link show $TUNNEL_DEV >/dev/null 2>&1; then
        echo -e "${YELLOW}Device $TUNNEL_DEV already exists.${NC}"
        read -p "Remove existing device? (y/n): " REMOVE_EXISTING
        if [[ "$REMOVE_EXISTING" == "y" ]]; then
            ip link set $TUNNEL_DEV down 2>/dev/null
            ip tunnel del $TUNNEL_DEV 2>/dev/null
        else
            echo -e "${RED}Cannot proceed. Device exists.${NC}"
            sleep 2
            return
        fi
    fi
    
    # Get tunnel configuration
    read -p "Enter Iran Public IP: " IRAN_IP
    read -p "Enter Foreign Public IP: " KHAREJ_IP
    read -p "Enter Foreign local IP [default: 10.10.0.1]: " FOREIGN_LOCAL_IP
    FOREIGN_LOCAL_IP=${FOREIGN_LOCAL_IP:-10.10.0.1}
    
    # Validate IPs
    for ip in "$IRAN_IP" "$KHAREJ_IP" "$FOREIGN_LOCAL_IP"; do
        if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${RED}Invalid IP address: $ip${NC}"
            sleep 2
            return
        fi
    done
    
    # Save configuration
    cat > "$CONFIG_DIR/$TUNNEL_NAME.conf" << EOF
# GRE Tunnel Configuration - $TUNNEL_NAME
TUNNEL_NAME="$TUNNEL_NAME"
TUNNEL_DEV="$TUNNEL_DEV"
TUNNEL_TYPE="foreign"
IRAN_PUBLIC_IP="$IRAN_IP"
KHAREJ_PUBLIC_IP="$KHAREJ_IP"
FOREIGN_LOCAL_IP="$FOREIGN_LOCAL_IP"
CREATED_DATE="$(date)"
EOF
    
    # Create setup script
    cat > "/usr/local/bin/gre-$TUNNEL_NAME.sh" << EOF
#!/bin/bash
# Setup script for $TUNNEL_NAME

# Load configuration
source $CONFIG_DIR/$TUNNEL_NAME.conf

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-gre-forward.conf
sysctl -p /etc/sysctl.d/99-gre-forward.conf

# Remove existing tunnel
ip link set \$TUNNEL_DEV down 2>/dev/null
ip tunnel del \$TUNNEL_DEV 2>/dev/null

# Flush iptables rules for this tunnel
iptables -D FORWARD -i \$TUNNEL_DEV -o \$DEFAULT_IFACE -j ACCEPT 2>/dev/null
iptables -D FORWARD -i \$DEFAULT_IFACE -o \$TUNNEL_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -t nat -D POSTROUTING -o \$DEFAULT_IFACE -j MASQUERADE 2>/dev/null

# Create tunnel
ip tunnel add \$TUNNEL_DEV mode gre remote \$IRAN_PUBLIC_IP local \$KHAREJ_PUBLIC_IP ttl 225
ip addr add \$FOREIGN_LOCAL_IP/30 dev \$TUNNEL_DEV
ip link set \$TUNNEL_DEV up

# Get default interface
DEFAULT_IFACE=\$(ip route | grep default | awk '{print \$5}' | head -n 1)

# Configure iptables
iptables -t nat -A POSTROUTING -o \$DEFAULT_IFACE -j MASQUERADE
iptables -A FORWARD -i \$TUNNEL_DEV -o \$DEFAULT_IFACE -j ACCEPT
iptables -A FORWARD -i \$DEFAULT_IFACE -o \$TUNNEL_DEV -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i \$TUNNEL_DEV -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4 2>/dev/null

# Log the setup
echo "\$(date): Foreign tunnel \$TUNNEL_DEV (\$TUNNEL_NAME) started" >> $LOG_DIR/$TUNNEL_NAME.log
EOF
    
    chmod +x "/usr/local/bin/gre-$TUNNEL_NAME.sh"
    
    # Create service file
    cat > "/etc/systemd/system/gre-$TUNNEL_NAME.service" << EOF
[Unit]
Description=GRE Foreign Tunnel - $TUNNEL_NAME
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/gre-$TUNNEL_NAME.sh
ExecStop=/bin/bash -c "ip link set $TUNNEL_DEV down 2>/dev/null; ip tunnel del $TUNNEL_DEV 2>/dev/null; echo \"\$(date): Tunnel stopped\" >> $LOG_DIR/$TUNNEL_NAME.log"
WorkingDirectory=/root
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    
    # Execute setup
    echo -e "\n${YELLOW}[*] Configuring tunnel...${NC}"
    /usr/local/bin/gre-$TUNNEL_NAME.sh
    
    # Enable service
    systemctl daemon-reload
    systemctl enable "gre-$TUNNEL_NAME.service"
    systemctl start "gre-$TUNNEL_NAME.service"
    
    echo -e "\n${GREEN}[✓] Foreign tunnel '$TUNNEL_NAME' setup complete!${NC}"
    echo -e "${CYAN}"
    echo "  Tunnel Device:    $TUNNEL_DEV"
    echo "  Local IP:         $FOREIGN_LOCAL_IP"
    echo "  Remote IP:        $IRAN_IP"
    echo "  Configuration:    $CONFIG_DIR/$TUNNEL_NAME.conf"
    echo "  Service:          gre-$TUNNEL_NAME.service"
    echo "  NAT:              Enabled"
    echo "  IP Forwarding:    Enabled"
    echo -e "${NC}"
    
    sleep 3
}

add_iranips() {
    bash <(curl -Ls https://raw.githubusercontent.com/rezvanniazi/gretunnel/main/iranips.sh) $DEFAULT_GW
}

manage_tunnel() {
    echo -e "${CYAN}[+] Tunnel Management${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════${NC}"
    
    # List available tunnels
    local config_files=($(ls $CONFIG_DIR/*.conf 2>/dev/null))
    
    if [ ${#config_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}No tunnel configurations found${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${YELLOW}Available Tunnels:${NC}"
    for i in "${!config_files[@]}"; do
        local tunnel_name=$(basename "${config_files[$i]}" .conf)
        local tunnel_type=$(grep "^TUNNEL_TYPE=" "${config_files[$i]}" 2>/dev/null | cut -d= -f2)
        echo -e "  $((i+1)). $tunnel_name (${tunnel_type:-unknown})"
    done
    
    echo ""
    echo -e "${CYAN}Management Options:${NC}"
    echo "  1) Start Tunnel"
    echo "  2) Stop Tunnel"
    echo "  3) Restart Tunnel"
    echo "  4) View Configuration"
    echo "  5) Delete Tunnel"
    echo "  0) Back to Main Menu"
    
    read -p "Select option [0-5]: " MGMT_CHOICE
    
    case $MGMT_CHOICE in
        1|2|3|4|5)
            read -p "Enter tunnel number: " TUNNEL_NUM
            if ! [[ "$TUNNEL_NUM" =~ ^[0-9]+$ ]] || [ "$TUNNEL_NUM" -lt 1 ] || [ "$TUNNEL_NUM" -gt ${#config_files[@]} ]; then
                echo -e "${RED}Invalid tunnel number${NC}"
                sleep 2
                return
            fi
            
            local selected_config="${config_files[$((TUNNEL_NUM-1))]}"
            local tunnel_name=$(basename "$selected_config" .conf)
            
            case $MGMT_CHOICE in
                1)
                    echo -e "${YELLOW}[*] Starting tunnel $tunnel_name...${NC}"
                    systemctl start "gre-$tunnel_name.service"
                    echo -e "${GREEN}[✓] Tunnel started${NC}"
                    ;;
                2)
                    echo -e "${YELLOW}[*] Stopping tunnel $tunnel_name...${NC}"
                    systemctl stop "gre-$tunnel_name.service"
                    echo -e "${GREEN}[✓] Tunnel stopped${NC}"
                    ;;
                3)
                    echo -e "${YELLOW}[*] Restarting tunnel $tunnel_name...${NC}"
                    systemctl restart "gre-$tunnel_name.service"
                    echo -e "${GREEN}[✓] Tunnel restarted${NC}"
                    ;;
                4)
                    echo -e "${CYAN}[*] Configuration for $tunnel_name:${NC}"
                    echo ""
                    cat "$selected_config"
                    echo ""
                    ;;
                5)
                    echo -e "${RED}[!] Deleting tunnel $tunnel_name${NC}"
                    read -p "Are you sure? (y/n): " CONFIRM_DELETE
                    if [[ "$CONFIRM_DELETE" == "y" ]]; then
                        # Stop and disable service
                        systemctl stop "gre-$tunnel_name.service" 2>/dev/null
                        systemctl disable "gre-$tunnel_name.service" 2>/dev/null
                        
                        # Remove tunnel interface
                        local tunnel_dev=$(grep "^TUNNEL_DEV=" "$selected_config" 2>/dev/null | cut -d= -f2)
                        if [ -n "$tunnel_dev" ]; then
                            ip link set "$tunnel_dev" down 2>/dev/null
                            ip tunnel del "$tunnel_dev" 2>/dev/null
                        fi
                        
                        # Remove files
                        rm -f "/etc/systemd/system/gre-$tunnel_name.service"
                        rm -f "/usr/local/bin/gre-$tunnel_name.sh"
                        rm -f "$selected_config"
                        rm -f "$CONFIG_DIR/$tunnel_name-routes.conf"
                        
                        # Remove from crontab
                        crontab -l 2>/dev/null | grep -v "#gre-$tunnel_name#" | crontab -
                        
                        echo -e "${GREEN}[✓] Tunnel $tunnel_name deleted${NC}"
                    fi
                    ;;
            esac
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    sleep 2
}

uninstall_all() {
    echo -e "${RED}[!] UNINSTALL ALL GRE TUNNELS${NC}"
    echo -e "${YELLOW}This will remove ALL tunnels and configurations${NC}"
    read -p "Are you absolutely sure? (type 'YES' to confirm): " CONFIRM
    
    if [[ "$CONFIRM" != "YES" ]]; then
        echo -e "${GREEN}Cancelled${NC}"
        sleep 2
        return
    fi
    
    echo -e "${YELLOW}[*] Removing all GRE tunnels...${NC}"
    
    # Stop and remove all services
    for service_file in /etc/systemd/system/gre-*.service 2>/dev/null; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file")
            systemctl stop "$service_name" 2>/dev/null
            systemctl disable "$service_name" 2>/dev/null
            rm -f "$service_file"
        fi
    done
    
    # Remove all tunnel interfaces
    for tunnel in $(ip link show 2>/dev/null | grep "gre[0-9]:" | awk -F: '{print $2}' | tr -d ' '); do
        ip link set "$tunnel" down 2>/dev/null
        ip tunnel del "$tunnel" 2>/dev/null
    done
    
    # Remove scripts
    rm -f /usr/local/bin/gre-*.sh
    rm -f /root/tunnel_setup.sh
    
    # Remove configurations
    rm -rf $CONFIG_DIR/*
    
    # Remove DNS lock
    chattr -i /etc/resolv.conf 2>/dev/null
    
    # Remove all GRE-related cron jobs
    crontab -l 2>/dev/null | grep -v "gre-" | crontab -
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}[✓] All GRE tunnels and configurations removed${NC}"
    sleep 2
}

# Main menu
while true; do
    draw_header
    echo -e "${CYAN}Main Menu:${NC}"
    echo " 1) Setup IRAN Tunnel"
    echo " 2) Setup FOREIGN Tunnel"
    echo " 3) Add IRAN Ips "
    echo " 4) List All Tunnels"
    echo " 5) Tunnel Status Dashboard"
    echo " 6) Manage Tunnel"
    echo " 7) Uninstall ALL Tunnels"
    echo " 0) Exit"
    echo ""
    read -p "Select option [0-6]: " CHOICE
    
    case $CHOICE in
        1) setup_iran ;;
        2) setup_foreign ;;
        3) add_iranips ;;
        4) list_tunnels ;;
        5) tunnel_status ;;
        6) manage_tunnel ;;
        7) uninstall_all ;;
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            sleep 1
            ;;
    esac
done
