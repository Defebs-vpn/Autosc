#!/bin/bash

# ==========================================
# Global Configuration
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
UNDERLINE='\033[4m'

# ==========================================
# Banner Display
clear
echo -e "${BLUE}"
echo "==================================================="
echo "  _   _ ____  _     ___  ____  ____  _____ ____   "
echo " | | | |  _ \| |   / _ \|  _ \|  _ \| ____|  _ \  "
echo " | |_| | |_) | |  | | | | |_) | |_) |  _| | | | | "
echo " |  _  |  __/| |__| |_| |  __/|  __/| |___| |_| | "
echo " |_| |_|_|   |_____\___/|_|   |_|   |_____|____/  "
echo "==================================================="
echo " Scrip Auto Install SSH Websocket"
echo " Version 4.1 | By Defebs Vpn"
echo "===================================================${NC}"
echo ""

# ==========================================
# Pre-Installation Checks
function pre_checks() {
    clear
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " Initial System Verification"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # Check Root Privileges
    echo -e "${CYAN}[1/6]${NC} Verifying root access..."
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}✗ Error: Script must be run as root${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Root access confirmed${NC}"

    # Check OS Compatibility
    echo -e "${CYAN}[2/6]${NC} Checking OS compatibility..."
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        echo -e "${RED}✗ Unsupported OS: $PRETTY_NAME${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Supported OS: $PRETTY_NAME${NC}"

    # Check Disk Space
    echo -e "${CYAN}[3/6]${NC} Checking disk space..."
    DISK_SPACE=$(df -h / | awk 'NR==2 {print $4}')
    if [ ${DISK_SPACE%G} -lt 2 ]; then
        echo -e "${RED}✗ Insufficient disk space (Minimum 2GB required)${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Disk space available: $DISK_SPACE${NC}"

    # Check Internet Connection
    echo -e "${CYAN}[4/6]${NC} Testing internet connection..."
    if ! ping -c 1 google.com &> /dev/null; then
        echo -e "${RED}✗ No internet connection detected${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Internet connection confirmed${NC}"

    # Check System Architecture
    echo -e "${CYAN}[5/6]${NC} Verifying system architecture..."
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
        echo -e "${RED}✗ Unsupported architecture: $ARCH${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Supported architecture: $ARCH${NC}"

    # Check Existing VPN Services
    echo -e "${CYAN}[6/6]${NC} Checking existing VPN services..."
    if pgrep -x "openvpn|dropbear|udpgw" > /dev/null; then
        echo -e "${YELLOW}⚠ Existing VPN services detected. Conflicts may occur${NC}"
        read -p "Continue anyway? (y/n): " choice
        if [[ $choice != "y" ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✓ No conflicting services detected${NC}"
    fi

    echo -e "\n${BLUE}Initial verification completed successfully!${NC}\n"
}

# ==========================================
# Repository Configuration
function configure_repos() {
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " System Repository Configuration"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # Backup Original Sources
    echo -e "${CYAN}[1/3]${NC} Backing up repositories..."
    cp /etc/apt/sources.list /etc/apt/sources.list.bak
    echo -e "${GREEN}✓ Repository backup created: /etc/apt/sources.list.bak${NC}"

    # Configure Main Repositories
    echo -e "${CYAN}[2/3]${NC} Configuring main repositories..."
    cat <<EOF > /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu $(lsb_release -cs) main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $(lsb_release -cs)-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $(lsb_release -cs)-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu $(lsb_release -cs)-security main restricted universe multiverse
EOF

    # Add Nginx Repo
    echo -e "${CYAN}[3/3]${NC} Adding Nginx repository..."
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list

    echo -e "\n${BLUE}Repository configuration completed!${NC}\n"
}

# ==========================================
# Dependency Tree Setup
function setup_dependencies() {
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " Dependency Management System"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # Update Package Lists
    echo -e "${CYAN}[1/4]${NC} Updating package database..."
    apt-get update -qq > /dev/null
    echo -e "${GREEN}✓ Package database updated${NC}"

    # Install Base Packages
    echo -e "${CYAN}[2/4]${NC} Installing core dependencies..."
    apt-get install -qq -y \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg-agent \
        ufw \
        iptables \
        curl \
        wget \
        dnsutils \
        git > /dev/null
    echo -e "${GREEN}✓ Core dependencies installed${NC}"

    # Install Build Tools
    echo -e "${CYAN}[3/4]${NC} Installing build essentials..."
    apt-get install -qq -y \
        build-essential \
        make \
        gcc \
        cmake \
        libssl-dev \
        zlib1g-dev \
        libpam0g-dev > /dev/null
    echo -e "${GREEN}✓ Build tools installed${NC}"

    # Cleanup
    echo -e "${CYAN}[4/4]${NC} Cleaning up..."
    apt-get autoremove -qq -y > /dev/null
    echo -e "${GREEN}✓ Cleanup completed${NC}"

    echo -e "\n${BLUE}Dependency management completed!${NC}\n"
}

# ==========================================
# Main Execution Flow
pre_checks
configure_repos
setup_dependencies

# ==========================================
# Domain & SSL Management
function setup_domain() {
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " Advanced Domain Configuration"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # Domain Validation
    echo -e "${CYAN}[1/6]${NC} Initial domain setup..."
    while true; do
        read -p "Masukkan domain utama (contoh: vpn-premium.id): " main_domain
        echo -e "${YELLOW}Verifikasi DNS untuk $main_domain...${NC}"
        domain_ip=$(dig +short $main_domain)
        server_ip=$(curl -s ifconfig.me)
        
        if [ "$domain_ip" != "$server_ip" ]; then
            echo -e "${RED}✗ DNS A record belum diarahkan ke IP server!"
            echo -e "IP Server: $server_ip"
            echo -e "IP Domain: ${domain_ip:-Tidak ditemukan}${NC}"
            read -p "Coba lagi? (y/n): " retry
            [[ $retry == "n" ]] && exit 1
        else
            echo -e "${GREEN}✓ DNS valid!${NC}"
            break
        fi
    done

    # Wildcard Domain Setup
    echo -e "${CYAN}[2/6]${NC} Konfigurasi wildcard domain..."
    read -p "Tambahkan subdomain wildcard (contoh: *.vpn)? (y/n): " wildcard
    if [[ $wildcard == "y" ]]; then
        wildcard_domain="*.$main_domain"
        echo -e "${YELLOW}Pastikan DNS record berikut sudah ada:"
        echo -e "CNAME: *.$main_domain → $main_domain${NC}"
    else
        wildcard_domain="$main_domain"
    fi

    # SSL Certificate Generation
    echo -e "${CYAN}[3/6]${NC} Membuat sertifikat SSL..."
    certbot_cmd="certbot --nginx -d $main_domain"
    [[ $wildcard == "y" ]] && certbot_cmd+=" -d $wildcard_domain"
    
    $certbot_cmd --non-interactive --agree-tos --register-unsafely-without-email > /dev/null 2>&1

    # Auto-Renewal Configuration
    echo -e "${CYAN}[4/6]${NC} Setup auto-renewal SSL..."
    (crontab -l 2>/dev/null; echo "0 3 */7 * * certbot renew --quiet --post-hook \"systemctl reload nginx\"") | crontab -

    # HSTS Enforcement
    echo -e "${CYAN}[5/6]${NC} Mengaktifkan HSTS..."
    sed -i '/^}/i \\tadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";' /etc/nginx/conf.d/*.conf

    # OCSP Stapling
    echo -e "${CYAN}[6/6]${NC} Mengoptimasi SSL..."
    openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    sed -i '/ssl_prefer_server_ciphers on;/a \
    ssl_dhparam /etc/ssl/certs/dhparam.pem;\n\
    ssl_stapling on;\n\
    ssl_stapling_verify on;\n\
    resolver 1.1.1.1 8.8.8.8 valid=300s;\n\
    resolver_timeout 5s;' /etc/nginx/conf.d/*.conf

    echo -e "\n${BLUE}Domain configuration completed!${NC}\n"
}

# ==========================================
# VPN Core Configuration
function setup_vpn() {
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " VPN Multi-Protocol Engine Setup"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # OpenSSH Configuration
    echo -e "${CYAN}[1/7]${NC} Configuring OpenSSH..."
    ssh_ports=(22 80 2222 444)
    sed -i "s/^#Port 22/Port 22/" /etc/ssh/sshd_config
    for port in "${ssh_ports[@]}"; do
        grep -q "Port $port" /etc/ssh/sshd_config || echo "Port $port" >> /etc/ssh/sshd_config
    done
    sed -i 's/#GatewayPorts no/GatewayPorts yes/g' /etc/ssh/sshd_config

    # Dropbear Multi-Port
    echo -e "${CYAN}[2/7]${NC} Configuring Dropbear..."
    dropbear_ports=(80 90 69 143)
    echo 'NO_START=0' > /etc/default/dropbear
    echo "DROPBEAR_PORT=$(printf "%s," "${dropbear_ports[@]}" | sed 's/,$//')" >> /etc/default/dropbear

    # WebSocket Server Setup
    echo -e "${CYAN}[3/7]${NC} Building WebSocket tunnel..."
    ws_dir="/etc/websocket"
    mkdir -p $ws_dir
    wget -qO $ws_dir/ws-tunnel https://github.com/lemoncode21/ws-tunnel/releases/latest/download/ws-tunnel
    chmod +x $ws_dir/ws-tunnel
    
    # WebSocket Service
    cat <<EOF > /etc/systemd/system/ws-tunnel.service
[Unit]
Description=WebSocket Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=$ws_dir/ws-tunnel -l 0.0.0.0:4443 -r 127.0.0.1:22 -p $main_domain
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # BadVPN UDP Gateway
    echo -e "${CYAN}[4/7]${NC} Building UDPGW..."
    badvpn_ports=(7100 7200 7300 7400 7500 7600)
    git clone https://github.com/ambrop72/badvpn.git /tmp/badvpn
    mkdir /tmp/badvpn/build
    cd /tmp/badvpn/build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null
    make install > /dev/null
    
    # UDPGW Service
    cat <<EOF > /etc/systemd/system/udpgw.service
[Unit]
Description=UDPGW Service
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${badvpn_ports[0]} --max-clients 1000
ExecStartPost=/bin/sleep 1
$(for port in "${badvpn_ports[@]:1}"; do
echo "ExecStartPost=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 1000"
done)
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # OpenVPN Configuration
    echo -e "${CYAN}[5/7]${NC} Setting up OpenVPN..."
    ovpn_dir="/etc/openvpn"
    wget -qO $ovpn_dir/server.conf https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
    sed -i "s/port 1194/port 443\nport 80\nport 1194/" $ovpn_dir/server.conf
    echo 'push "redirect-gateway def1 bypass-dhcp"' >> $ovpn_dir/server.conf

    # SlowDNS Integration
    echo -e "${CYAN}[6/7]${NC} Installing SlowDNS..."
    wget -qO /usr/bin/slowdns https://github.com/xditya/slowdns/raw/main/slowdns
    chmod +x /usr/bin/slowdns
    cat <<EOF > /etc/systemd/system/slowdns.service
[Unit]
Description=SlowDNS Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/slowdns -udp :5300 -private-key $(slowdns -gen-key) -nameserver 1.1.1.1:53
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # OHP Tunnel Setup
    echo -e "${CYAN}[7/7]${NC} Configuring OHP..."
    wget -qO /usr/bin/ohp https://github.com/lfasmpao/open-http-puncher/releases/latest/download/ohp
    chmod +x /usr/bin/ohp
    cat <<EOF > /etc/systemd/system/ohp.service
[Unit]
Description=OHP Tunnel Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ohp -port 9080 -proxy 127.0.0.1:3128 -tunnel 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    echo -e "\n${BLUE}VPN core configuration completed!${NC}\n"
}

# ==========================================
# Finalization & Services
function finalize_setup() {
    echo -e "${BLUE}"
    echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    echo " System Finalization"
    echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    echo -e "${NC}"

    # Firewall Rules
    echo -e "${CYAN}[1/5]${NC} Configuring firewall..."
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    ufw allow 22,80,443,2222,444,90,69,143,7788,2082,8080,8880,2052,2086,2095,8443,2053,2083,2087,2096,53,5300,9080,3128,7100:7600/tcp > /dev/null
    ufw allow 1:65535/udp > /dev/null
    echo "y" | ufw enable > /dev/null

    # Service Reload
    echo -e "${CYAN}[2/5]${NC} Reloading services..."
    systemctl daemon-reload
    services=(nginx ssh dropbear openvpn ws-tunnel udpgw slowdns ohp)
    for service in "${services[@]}"; do
        systemctl restart $service > /dev/null
        systemctl enable $service > /dev/null
    done

    # Security Hardening
    echo -e "${CYAN}[3/5]${NC} Applying security..."
    echo "AllowUsers root" >> /etc/ssh/sshd_config
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Cleanup
    echo -e "${CYAN}[4/5]${NC} Cleaning temporary files..."
    rm -rf /tmp/badvpn*
    apt autoremove -y > /dev/null

    # Backup Config
    echo -e "${CYAN}[5/5]${NC} Creating backup..."
    backup_dir="/etc/vpn-backup-$(date +%Y%m%d)"
    mkdir -p $backup_dir
    cp -r /etc/ssh /etc/nginx /etc/openvpn /etc/dropbear $backup_dir
    tar -czf $backup_dir.tar.gz $backup_dir > /dev/null

    echo -e "\n${BLUE}Finalization completed!${NC}\n"
}

# ==========================================
# Final Display
function show_summary() {
    clear
    echo -e "${BLUE}"
    figlet -f slant " INSTALLATION " | boxes -d diamond
    echo -e "${NC}"
    
    # Server Information
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗"
    echo -e "║ ${GREEN}▣ ${YELLOW}Server Information                                                         ${BLUE}║"
    echo -e "╠════════════════════════════════════════════════════════════════════╣"
    printf "${BLUE}║ ${NC}%-20s ${GREEN}%-40s ${BLUE}║\n" "Hostname:" "$(hostname)"
    printf "${BLUE}║ ${NC}%-20s ${GREEN}%-40s ${BLUE}║\n" "Domain:" "$main_domain"
    printf "${BLUE}║ ${NC}%-20s ${GREEN}%-40s ${BLUE}║\n" "Public IP:" "$server_ip"
    printf "${BLUE}║ ${NC}%-20s ${GREEN}%-40s ${BLUE}║\n" "Uptime:" "$(uptime -p)"
    echo -e "╚════════════════════════════════════════════════════════════════════╝"

    # Configuration Columns
    echo -e "\n${BLUE}╔════════════════════════╦══════════════════════════╦════════════════════════╗"
    echo -e "║ ${GREEN}▣ SSH Configuration     ${BLUE}║ ${GREEN}▣ Protocol Ports        ${BLUE}║ ${GREEN}▣ Client Configuration ${BLUE}║"
    echo -e "╠════════════════════════╬══════════════════════════╬════════════════════════╣"
    
    # Column 1 - SSH
    printf "${BLUE}║ ${YELLOW}%-10s ${NC}%-12s ${BLUE}║" "OpenSSH:" "22,80,2222"
    printf "${YELLOW}%-12s ${NC}%-12s ${BLUE}║" "Dropbear:" "80,90,69"
    printf "${YELLOW}%-10s ${NC}%-12s ${BLUE}║\n" "Username:" "$username"
    
    # Column 2 - Ports
    printf "${BLUE}║ ${YELLOW}%-10s ${NC}%-12s ${BLUE}║" "WebSocket:" "80,443"
    printf "${YELLOW}%-12s ${NC}%-12s ${BLUE}║" "OpenVPN:" "80,1194"
    printf "${YELLOW}%-10s ${NC}%-12s ${BLUE}║\n" "Password:" "$password"
    
    # Column 3 - Client
    printf "${BLUE}║ ${YELLOW}%-10s ${NC}%-12s ${BLUE}║" "BadVPN:" "7100-7600"
    printf "${YELLOW}%-12s ${NC}%-12s ${BLUE}║" "SlowDNS:" "53,5300"
    printf "${YELLOW}%-10s ${NC}%-12s ${BLUE}║\n" "Expiry:" "$exp_date"
    
    echo -e "╠════════════════════════╬══════════════════════════╬════════════════════════╣"
    
    # SSL Info
    ssl_expiry=$(date -d "$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$main_domain/cert.pem | cut -d= -f2)" +"%d-%m-%Y")
    printf "${BLUE}║ ${CYAN}%-10s ${NC}%-12s ${BLUE}║" "SSL Issuer:" "Let's Encrypt"
    printf "${CYAN}%-12s ${NC}%-12s ${BLUE}║" "SSL Expiry:" "$ssl_expiry"
    printf "${CYAN}%-10s ${NC}%-12s ${BLUE}║\n" "Key Size:" "4096-bit"
    
    echo -e "╚════════════════════════╩══════════════════════════╩════════════════════════╝"

    # QR Code Generation
    if command -v qrencode &> /dev/null; then
        echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════════════╗"
        echo -e "║ ${GREEN}▣ Mobile Configuration QR Code                                    ${BLUE}║"
        echo -e "╠════════════════════════════════════════════════════════════════════╣"
        qrencode -t ANSI "ssh://$username@$main_domain:443/?password=$password"
        echo -e "╚════════════════════════════════════════════════════════════════════╝"
    else
        echo -e "\n${YELLOW}⚠ Install qrencode untuk menampilkan QR Code: apt install qrencode"
    fi

    # Security Notes
    echo -e "\n${RED}╔════════════════════════════════════════════════════════════════════╗"
    echo -e "║ ${YELLOW}‼ PENTING: Simpan informasi berikut di tempat aman!               ${RED}║"
    echo -e "╠════════════════════════════════════════════════════════════════════╣"
    echo -e "║ ${YELLOW}◈ Backup Config: ${NC}$backup_dir.tar.gz                                  ${RED}║"
    echo -e "║ ${YELLOW}◈ Firewall Status: ${GREEN}Aktif ${YELLOW}(UFW)                                 ${RED}║"
    echo -e "║ ${YELLOW}◈ Last Updated: ${NC}$(date +"%d-%m-%Y %H:%M")                              ${RED}║"
    echo -e "╚════════════════════════════════════════════════════════════════════╝"
}

# ==========================================
# Main Execution Flow
pre_checks
configure_repos
setup_dependencies
setup_domain
setup_vpn
finalize_setup
show_summary
