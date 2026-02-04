cat << 'EOF' > /usr/local/bin/gre && chmod +x /usr/local/bin/gre
#!/bin/bash
# GRE Master v6.5 - Absolute DNS Overwrite
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

draw_header() {
    clear
    IP_INFO=$(curl -s --max-time 2 http://ip-api.com/json/ || echo "{}")
    ISP=$(echo $IP_INFO | grep -oP '(?<="isp":")[^"]*' || echo "Unknown ISP")
    echo -e "${CYAN}      ________ __________ __________"
    echo "     /  _____/ \______   \\______   \\"
    echo "    /   \  ___  |       _/ |    |  _/"
    echo "    \    \_\  \ |    |   \ |    |   \\"
    echo "     \______  / |____|_  / |______  /"
    echo "            \/         \/         \/ ${NC}"
    echo -e "${GREEN} GRE Dashboard v6.5 | DC: $ISP ${NC}"
    echo -e "--------------------------------------------"
}

setup_iran() {
    read -p " Enter Iran Public IP: " IRAN_IP
    read -p " Enter Foreign Public IP: " KHAREJ_IP
    
    cat << 'INS' > /root/tunnel_setup.sh
#!/bin/bash
IRAN_IP=$1
KHAREJ_IP=$2
GW=$(ip route | grep default | awk '{print $3}' | head -n 1)

# Interface Setup
ip link set gre1 down 2>/dev/null
ip tunnel del gre1 2>/dev/null
ip tunnel add gre1 mode gre remote $KHAREJ_IP local $IRAN_IP ttl 225
ip addr add 10.10.0.2/30 dev gre1
ip link set gre1 up
ip route add $KHAREJ_IP via $GW 2>/dev/null

# --- Absolute DNS Fix (Breaking Symlinks) ---
chattr -i /etc/resolv.conf 2>/dev/null
rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" > /etc/resolv.conf
chattr +i /etc/resolv.conf

# --- MANUAL ROUTES BELOW ---
INS

    echo -e "${YELLOW}Step: Paste your Iran Routes below.${NC}"
    echo -e "${CYAN}After pasting, press [Enter] then [Ctrl+D] to save.${NC}"
    cat >> /root/tunnel_setup.sh

    echo "ip route replace default via 10.10.0.1 2>/dev/null" >> /root/tunnel_setup.sh
    chmod +x /root/tunnel_setup.sh
    /bin/bash /root/tunnel_setup.sh "$IRAN_IP" "$KHAREJ_IP"

    # Create Service
    cat << SVC > /etc/systemd/system/gre.service
[Unit]
Description=GRE Tunnel
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash /root/tunnel_setup.sh $IRAN_IP $KHAREJ_IP
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SVC
    
    systemctl daemon-reload && systemctl enable gre.service
    
    read -p " Enter Reboot Cycle (Hours): " HR
    (crontab -l 2>/dev/null | grep -v "/sbin/reboot"; echo "0 */$HR * * * /sbin/reboot") | crontab -
    echo -e "${GREEN}Iran Setup Complete! DNS is now ONLY 1.1.1.1${NC}"
    sleep 2
}

setup_foreign() {
    read -p " Enter Iran Public IP: " IRAN_IP
    read -p " Enter Foreign Public IP: " KHAREJ_IP
    cat << 'OUT' > /root/tunnel_setup.sh
#!/bin/bash
IRAN_IP=$1
KHAREJ_IP=$2
echo 1 > /proc/sys/net/ipv4/ip_forward
ip link set gre1 down 2>/dev/null
ip tunnel del gre1 2>/dev/null
iptables -t nat -F && iptables -F
ip tunnel add gre1 mode gre remote $IRAN_IP local $KHAREJ_IP ttl 225
ip addr add 10.10.0.1/30 dev gre1
ip link set gre1 up
IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
iptables -A FORWARD -i gre1 -o $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -o gre1 -m state --state RELATED,ESTABLISHED -j ACCEPT
OUT
    chmod +x /root/tunnel_setup.sh
    /bin/bash /root/tunnel_setup.sh "$IRAN_IP" "$KHAREJ_IP"
    
    cat << SVC > /etc/systemd/system/gre.service
[Unit]
Description=GRE Foreign
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash /root/tunnel_setup.sh $IRAN_IP $KHAREJ_IP
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload && systemctl enable gre.service
    echo -e "${GREEN}Foreign Setup Complete!${NC}"
    sleep 2
}


while true; do
    draw_header
    echo " 1) Setup IRAN Server (Manual Routes + DNS Force)"
    echo " 2) Setup FOREIGN Server"
    echo " 3) Uninstall GRE"
    echo " 0) Exit"
    read -p " Select: " CH
    case $CH in
        1) setup_iran ;;
        2) setup_foreign ;;
        3) 
            chattr -i /etc/resolv.conf 2>/dev/null
            systemctl stop gre 2>/dev/null
            systemctl disable gre 2>/dev/null
            ip tunnel del gre1 2>/dev/null
            rm -f /etc/systemd/system/gre.service /root/tunnel_setup.sh
            echo "Uninstalled."; sleep 2 ;;
        0) exit 0 ;;
    esac
done
EOF
gre
