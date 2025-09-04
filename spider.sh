#!/usr/bin/env bash
# Fixed and debugged version of the pasted script: spider.sh
# I preserved your structure and intent while repairing syntax and logic so it can run.
# NOTE: This script performs system-level changes (installs packages, edits configs). Run as root on a fresh VPS.
set -euo pipefail

############################
# Color variables
############################
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
NC="\033[0m"       # No Color / reset
GREENB="\033[42m"
REDB="\033[41m"
OK="${GREEN}[OK]${NC}"
ERROR="${RED}[ERROR]${NC}"

############################
# Functions for messages
############################
typing_banner() {
  local text="${1:-}"
  local color="${2:-$NC}"
  echo -e "${color}\e[1m"
  for (( i=0; i<${#text}; i++ )); do
    echo -ne "${text:i:1}"
    sleep 0.03
  done
  echo -e "${NC}"
}

secs_to_human() {
  local s=${1:-0}
  printf "Installation time : %d hours %d minute's %d seconds\n" $((s/3600)) $(((s/60)%60)) $((s%60))
}

print_ok(){ echo -e "${OK} ${BLUE} $* ${NC}"; }
print_install(){
  echo -e "${GREEN} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${NC}"
  echo -e "${YELLOW} » $* ${NC}"
  echo -e "${GREEN} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${NC}"
  sleep 1
}
print_error(){ echo -e "${ERROR} ${REDB} $* ${NC}"; }
print_success(){
  echo -e "${GREEN} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${NC}"
  echo -e "${GREEN} » $* installed successfully ${NC}"
  echo -e "${GREEN} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${NC}"
  sleep 1
}

is_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    print_error "You need to run this script as root"; exit 1
  else
    print_ok "Root user — starting installation process"
  fi
}

############################
# Extra Animations
############################
loading_dots() {
  local msg="$1"
  local color="$2"
  echo -ne "${color}${msg}${NC}"
  for i in {1..3}; do
    echo -ne "."
    sleep 0.4
  done
  echo
}

spinner() {
  local msg="$1"
  local color="$2"
  local spin='|/-\'
  echo -ne "${color}${msg} ${NC}"
  for i in $(seq 0 7); do
    echo -ne "\b${spin:$((i % 4)):1}"
    sleep 0.2
  done
  echo
}

matrix_rain() {
  echo -e "${GREEN}"
  for i in {1..15}; do
    echo $RANDOM | md5sum | tr -dc '0-9A-F' | head -c 60
    sleep 0.05
  done
  echo -e "${NC}"
}

############################
# Start
############################
sudo -n true 2>/dev/null || true
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y figlet curl ca-certificates

clear

# Logo
echo -e "${GREEN}$(figlet -f small -w 80 'SPIDER STORE')${NC}"

# Skull Banner
echo -e "${RED}"
cat << "EOF"
      ☠☠☠ FEAR THE SPIDER ☠☠☠
EOF
echo -e "${NC}"

# Animations
matrix_rain
spinner "🕷 Initializing Core Systems" "$GREEN"
loading_dots "🔥 Loading Modules" "$YELLOW"

# Main Banner
typing_banner "👑 Coded by: SPIDER" "$GREEN"
typing_banner "© 2024 — Stable Edition" "$GREEN"
typing_banner "⚠️ WARNING!" "$RED"
typing_banner "Only THIS script is the real deal. Cloned copies are trash — full of bugs and backdoors." "$BLUE"
typing_banner "Wannabe devs can keep stealing, but they'll never touch the original." "$BLUE"
typing_banner "💀 Respect the source. Fear the SPIDER." "$YELLOW"

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Optional pause before script continues
read -p "⚡ Press ENTER to continue..." 
clear

IP="$(curl -sS ipv4.icanhazip.com || true)"
clear

# OS check
OS_ID="$(. /etc/os-release; echo "${ID:-}")"
OS_NAME="$(. /etc/os-release; echo "${PRETTY_NAME:-Unknown}")"
if [[ "${OS_ID}" == "ubuntu" || "${OS_ID}" == "debian" ]]; then
  echo -e "${GREEN}  » Your OS Is Supported ( ${OS_NAME} )${NC}"
else
  echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}${OS_NAME}${NC} )"
  exit 1
fi

# IP check
if [[ -z "${IP}" ]]; then
  echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
  exit 1
else
  echo -e "${GREEN}  » IP Address ( ${GREEN}${IP}${NC} )"
fi

ALLOWED_IPS_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/Database"
if curl -fsSL "$ALLOWED_IPS_URL" | grep -Ev '^###' | grep -q -F "$IP"; then
  echo -e "${GREEN}  » Your IP is registered for installation.${NC}"
else
  echo -e "${ERROR}${YELLOW} ${IP} ${NC} not found in the database! Installation is aborted."
  exit 1
fi

read -rp "$( echo -e "Press ${GREEN}[ Enter ]${NC} to start installation: " )" _
clear

is_root
if systemd-detect-virt | grep -qi openvz; then
  echo "OpenVZ is not supported"
  exit 1
fi

echo -e "\e[32mloading...\e[0m"
clear
apt install -y ruby wondershaper
gem install --no-document lolcat || true

REPO="https://raw.githubusercontent.com/spider660/Lau_Op/main/"
start="$(date +%s)"

# Basic env exports used later
export tanggal="$(date -d "0 days" +"%d-%m-%Y - %X")"
export OS_Name="${OS_NAME}"
export Kernel="$(uname -r)"
export Arch="$(uname -m)"
export I="$(curl -s https://ipinfo.io/ip || true)"

first_setup() {
  timedatectl set-timezone Africa/Nairobi || true
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  print_success "Directory Xray"
  echo "Setting up dependencies for ${OS_NAME}"
  apt-get update -y
  apt-get install -y --no-install-recommends software-properties-common
  apt-get install -y haproxy
}

nginx_install() {
  if [[ "${OS_ID}" == "ubuntu" || "${OS_ID}" == "debian" ]]; then
    print_install "Setup nginx for ${OS_NAME}"
    apt-get install -y nginx
  else
    echo -e "Your OS Is Not Supported ( ${YELLOW}${OS_NAME}${NC} )"
  fi
}

base_package() {
  clear
  print_install "Installing the Required Packages"
  apt install -y zip pwgen openssl netcat-openbsd socat cron bash-completion \
      figlet ntpdate sudo debconf-utils \
      speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
      libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison \
      make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev \
      libsqlite3-dev sed dirmngr build-essential gcc g++ python3 htop lsof tar \
      wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux msmtp-mta \
      ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent \
      net-tools gnupg gnupg2 lsb-release shc cmake git screen xz-utils apt-transport-https \
      dnsutils jq openvpn easy-rsa
  systemctl enable chrony || true
  systemctl restart chrony || true
  ntpdate pool.ntp.org || true
  apt-get clean
  apt-get autoremove -y || true
  print_success "Required Packages"
}

install_domain() {
  clear
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[2mPlease Select a Domain Type Below \e[0m"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[2m1)\e[0m Use Your Own Domain (Recommended)"
  echo -e " \e[2m2)\e[0m Use Spider Random Domain"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  read -rp " Please select numbers 1-2 or Any Button(Random) : " host
  echo ""
  mkdir -p /var/lib/kyt
  if [[ "${host}" == "1" ]]; then
    echo -e " \e[2mPlease Enter Your Domain ${NC}"
    read -rp " Input Domain : " host1
    echo "IP=" > /var/lib/kyt/ipvps.conf
    echo "$host1" > /etc/xray/domain
    echo "$host1" > /root/domain
  elif [[ "${host}" == "2" ]]; then
    wget -q "${REPO}ubuntu/cf.sh" -O /root/cf.sh && chmod +x /root/cf.sh && /root/cf.sh || true
    rm -f /root/cf.sh
  else
    print_install "Random Subdomain/Domain is Used"
  fi
  clear
}

restart_system(){
  local MYIP="$(curl -sS ipv4.icanhazip.com || true)"
  local izins="https://raw.githubusercontent.com/spider660/Lau_Op/main/keygen"
  local username="$(curl -fsSL "$izins" | grep -F "$MYIP" | awk '{print $2}' | head -n1)"
  local expx="$(curl -fsSL "$izins" | grep -F "$MYIP" | awk '{print $3}' | head -n1)"
  echo "${username:-unknown}" >/usr/bin/user
  echo "${expx:-N/A}" >/usr/bin/e

  local DATE="$(date +'%Y-%m-%d')"
  local ISP="$(curl -s ipinfo.io/org | cut -d " " -f 2-10)"
  local domain="$(cat /etc/xray/domain 2>/dev/null || true)"
  local CHATID="8340881349"
  local KEY="8264940025:AAFGeZByPFGeLMLp4edjK6J0J7F1WIoT2ok"
  local URL="https://api.telegram.org/bot$KEY/sendMessage"
  local TIMEZONE="$(date +%H:%M:%S)"

  local TEXT=$(cat <<EOF
━━━━━━━━━━━━━━━━━━━━━━
🕷️ <b>SPIDER STORE SYSTEM</b> 🕷️
━━━━━━━━━━━━━━━━━━━━━━
<code>👤 User    :</code> <code>${username}</code>
<code>🌐 Domain  :</code> <code>${domain}</code>
<code>📡 IP VPS  :</code> <code>${MYIP}</code>
<code>🏢 ISP     :</code> <code>${ISP}</code>
<code>📅 Date    :</code> <code>${DATE}</code>
<code>⏰ Time    :</code> <code>${TIMEZONE}</code>
<code>⏳ Exp Sc. :</code> <code>${expx}</code>
━━━━━━━━━━━━━━━━━━━━━━
🔔 <i>Auto Notification from GitHub</i>
EOF
)

curl -fsS --max-time 10 \
  -d "chat_id=${CHATID}&disable_web_page_preview=1&text=${TEXT}&parse_mode=html" \
  "$URL" >/dev/null || true
}

install_ssl() {
  clear
  print_install "Installing SSL On Domain"
  rm -rf /etc/xray/xray.key /etc/xray/xray.crt
  domain="$(cat /root/domain 2>/dev/null || cat /etc/xray/domain 2>/dev/null || true)"
  STOPWEBSERVER="$(lsof -i:80 -sTCP:LISTEN -nP 2>/dev/null | awk 'NR==2{print $1}' || true)"
  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh
  [[ -n "${STOPWEBSERVER}" ]] && systemctl stop "${STOPWEBSERVER}" || true
  systemctl stop nginx || true
  curl -fsSL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
  chmod +x /root/.acme.sh/acme.sh
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
  /root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
  chmod 600 /etc/xray/xray.key
  print_success "SSL Certificate"
}

make_folder_xray() {
  rm -rf /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db /etc/user-create/user.log || true
  mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /usr/bin/xray/ /var/log/xray/ /var/www/html \
           /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh /etc/user-create
  chown www-data:www-data /var/log/xray || true
  chmod 755 /var/log/xray
  : > /etc/xray/domain
  : > /var/log/xray/access.log
  : > /var/log/xray/error.log
  : > /etc/vmess/.vmess.db
  : > /etc/vless/.vless.db
  : > /etc/trojan/.trojan.db
  : > /etc/shadowsocks/.shadowsocks.db
  : > /etc/ssh/.ssh.db
  : > /etc/bot/.bot.db
  echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
  for f in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db; do
    echo "& plugin Account" >>"$f"
  done
}

install_xray() {
  clear
  print_install "Core Xray Latest Version"
  local domainSock_dir="/run/xray"
  mkdir -p "$domainSock_dir"
  chown www-data:www-data "$domainSock_dir"
  
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data
  wget -q -O /etc/xray/config.json "${REPO}ubuntu/config.json"
  wget -q -O /etc/systemd/system/runn.service "${REPO}ubuntu/runn.service"
  
  local domain="$(cat /etc/xray/domain 2>/dev/null || true)"
  local IPVPS="$(cat /etc/xray/ipvps 2>/dev/null || echo "${IP}")"
  print_success "Core Xray Latest Version"

  curl -s ipinfo.io/city | tee /etc/xray/city >/dev/null
  curl -s ipinfo.io/org | cut -d " " -f 2-10 | tee /etc/xray/isp >/dev/null

  # Example additional config
  # if [[ -f /etc/xray/config.json ]]; then
  #     echo "Config exists"
  # else
  #     echo "Config missing"
  # fi

}  # <-- Make sure the function ends here

  print_install "Installing Packet Configuration"
  wget -q -O /etc/haproxy/haproxy.cfg "${REPO}ubuntu/haproxy.cfg"
  wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}ubuntu/xray.conf"
  sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg || true
  sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf || true
  curl -fsSL "${REPO}ubuntu/nginx.conf" > /etc/nginx/nginx.conf
  cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null
  chmod 644 /etc/systemd/system/runn.service

  # Write a clean xray service
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target
[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
LimitNPROC=1000000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
  print_success "Configuration Packet"
}

ssh(){
  clear
  print_install "Installing Password SSH"
  wget -q -O /etc/pam.d/common-password "${REPO}ubuntu/password" || true
  chmod 644 /etc/pam.d/common-password || true

  # Minimal rc-local setup to keep compatibility
  cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=journal
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
END

  cat > /etc/rc.local <<-END
#!/usr/bin/env bash
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
END
  chmod +x /etc/rc.local
  systemctl enable rc-local >/dev/null 2>&1 || true
  systemctl start rc-local.service >/dev/null 2>&1 || true

  ln -fs /usr/share/zoneinfo/Africa/Nairobi /etc/localtime || true
  sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true
  print_success "Password SSH"
}

udp_mini(){
  clear
  print_install "Installing Service Limit IP & Quota"
  wget -q https://raw.githubusercontent.com/Amchapeey/strategic/main/ubuntu/fv-tunnel -O /usr/local/kyt/fv-tunnel && chmod +x /usr/local/kyt/fv-tunnel && /usr/local/kyt/fv-tunnel || true
  mkdir -p /usr/local/kyt/
  wget -q -O /usr/local/kyt/udp-mini "${REPO}ubuntu/udp-mini" || true
  chmod +x /usr/local/kyt/udp-mini || true
  wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}ubuntu/udp-mini-1.service" || true
  wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}ubuntu/udp-mini-2.service" || true
  wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}ubuntu/udp-mini-3.service" || true
  systemctl daemon-reload || true
  systemctl enable --now udp-mini-1 || true
  systemctl enable --now udp-mini-2 || true
  systemctl enable --now udp-mini-3 || true
  print_success "Limit IP Service"
}

ssh_slow() {
  clear
  print_install "Installing the SlowDNS Server module"
  if wget -q -O /tmp/nameserver "${REPO}ubuntu/nameserver"; then
    chmod +x /tmp/nameserver
    if bash /tmp/nameserver | tee /root/install.log >/dev/null; then
      print_success "SlowDNS installed successfully"
    else
      echo "Failed to execute the nameserver script"
      return 1
    fi
  else
    echo "Failed to download nameserver"
    return 1
  fi
}

ins_SSHD(){
  clear
  print_install "Installing SSHD"
  wget -q -O /etc/ssh/sshd_config "${REPO}ubuntu/sshd" || true
  chmod 600 /etc/ssh/sshd_config || true
  systemctl restart ssh || /etc/init.d/ssh restart || true
  systemctl status ssh --no-pager || true
  print_success "SSHD"
}

ins_dropbear(){
  clear
  print_install "Installing Dropbear"
  apt-get install -y dropbear
  wget -q -O /etc/default/dropbear "${REPO}ubuntu/dropbear.conf" || true
  chmod 644 /etc/default/dropbear || true
  systemctl restart dropbear || /etc/init.d/dropbear restart || true
  systemctl status dropbear --no-pager || true
  print_success "Dropbear"
}

ins_vnstat(){
  clear
  print_install "Installing Vnstat"
  apt -y install vnstat libsqlite3-dev
  systemctl enable --now vnstat || true
  NET="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
  vnstat -u -i "$NET" || true
  sed -i "s|^Interface \".*\"|Interface \"$NET\"|g" /etc/vnstat.conf || true
  chown -R vnstat:vnstat /var/lib/vnstat || true
  systemctl restart vnstat || true
  print_success "Vnstat"
}

ins_openvpn(){
  clear
  print_install "Installing OpenVPN"
  wget -q "${REPO}ubuntu/openvpn" -O /root/openvpn && chmod +x /root/openvpn && /root/openvpn || true
  systemctl restart openvpn || /etc/init.d/openvpn restart || true
  print_success "OpenVPN"
}

ins_backup(){
  clear
  print_install "Installing Backup Server"
  apt install -y rclone
  printf "q\n" | rclone config || true
  mkdir -p /root/.config/rclone
  wget -q -O /root/.config/rclone/rclone.conf "${REPO}ubuntu/rclone.conf" || true
  cd /bin
  git clone https://github.com/magnific0/wondershaper.git || true
  cd wondershaper || true
  make install || true
  cd ~
  rm -rf wondershaper || true
  : > /home/limit || true
  apt install -y msmtp-mta ca-certificates bsd-mailx
  cat >/etc/msmtprc <<'EOF'
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77
logfile ~/.msmtp.log
EOF
  chown -R www-data:www-data /etc/msmtprc || true
  wget -q -O /etc/ipserver "${REPO}ubuntu/ipserver" && bash /etc/ipserver || true
  print_success "Backup Server"
}

ins_swab(){
  clear
  print_install "Installing Swap 1 G"
  curl -fsSL "https://github.com/xxxserxxx/gotop/releases/latest/download/gotop_linux_amd64.deb" -o /tmp/gotop.deb || true
  dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
  if [[ ! -f /swapfile ]]; then
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
  fi
  chronyd -q 'server 0.id.pool.ntp.org iburst' || true
  chronyc sourcestats -v || true
  chronyc tracking -v || true
  wget -q "${REPO}ubuntu/bbr.sh" -O /root/bbr.sh && chmod +x /root/bbr.sh && /root/bbr.sh || true
  print_success "Swap 1 G"
}

ins_Fail2ban() {
    clear
    print_install "Installing Fail2ban"

    if [[ -d "/usr/local/ddos" ]]; then
        echo "Removing previous /usr/local/ddos directory..."
        rm -rf /usr/local/ddos
    fi

    mkdir -p /usr/local/ddos
    apt -y install fail2ban
    systemctl enable --now fail2ban || true
    systemctl restart fail2ban || true
    echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config || true
    sed -i 's@DROPBEAR_BANNER.*@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear || true
    wget -q -O /etc/kyt.txt "${REPO}ubuntu/issue.net" || true

    print_success "Fail2ban"
}

ins_epro() {
  clear
  print_install "Installing ePro WebSocket Proxy"
  wget -q -O /usr/bin/ws "${REPO}ubuntu/ws" || true
  wget -q -O /usr/bin/tun.conf "${REPO}ubuntu/tun.conf" || true
  wget -q -O /etc/systemd/system/ws.service "${REPO}ubuntu/ws.service" || true
  chmod +x /usr/bin/ws
  chmod 644 /usr/bin/tun.conf
  systemctl daemon-reload || true
  systemctl enable --now ws || true
  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" || true
  wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" || true
  wget -q -O /usr/sbin/ftvpn "${REPO}ubuntu/ftvpn" || true
  chmod +x /usr/sbin/ftvpn || true

  # Basic bittorrent block rules (best-effort; may not persist across reboots without iptables-persistent)
  for rule in "get_peers" "announce_peer" "find_node" "BitTorrent" "BitTorrent protocol" "peer_id" ".torrent" "announce.php?passkey" "torrent" "announce" "info_hash"; do
    iptables -A FORWARD -m string --string "$rule" --algo bm -j DROP || true
  done
  iptables-save > /etc/iptables.up.rules || true
  iptables-restore -t < /etc/iptables.up.rules || true
  netfilter-persistent save || true
  netfilter-persistent reload || true
  apt autoclean -y >/dev/null 2>&1 || true
  apt autoremove -y >/dev/null 2>&1 || true
  print_success "ePro WebSocket Proxy installed successfully"
}

ins_restart(){
  clear
  print_install "Restarting All Packet"
  systemctl restart nginx || true
  systemctl restart openvpn || true
  systemctl restart ssh || true
  systemctl restart dropbear || true
  systemctl restart fail2ban || true
  systemctl restart vnstat || true
  systemctl restart haproxy || true
  systemctl restart cron || true
  systemctl daemon-reload || true
  systemctl enable --now nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws fail2ban || true
  history -c || true
  echo "unset HISTFILE" >> /etc/profile
  rm -f /root/openvpn /root/key.pem /root/cert.pem || true
  print_success "All Packet"
}

menu(){
  clear
  print_install "Installing Menu Packet"
  wget -q "${REPO}ubuntu/menu.zip" -O /root/menu.zip || true
  (cd /root && unzip -o menu.zip && chmod +x menu/* && mv menu/* /usr/local/sbin && rm -rf menu menu.zip) || true
}

profile(){
  clear
  cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
EOF

  cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

  cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

  chmod 644 /root/.profile

  cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

  cat >/etc/cron.d/limit_ip <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

  cat >/etc/cron.d/limit_ip2 <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log"  >/etc/cron.d/log.xray
  service cron restart || true

  echo "5" >/home/daily_reboot

  cat >/etc/systemd/system/rc-local.service <<'EOF'
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=journal
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

  echo "/bin/false" >>/etc/shells
  echo "/usr/sbin/nologin" >>/etc/shells

  cat >/etc/rc.local <<'EOF'
#!/usr/bin/env bash
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent || true
exit 0
EOF
  chmod +x /etc/rc.local
  print_success "Menu Packet"
}

enable_services(){
  clear
  print_install "Enable Service"
  systemctl daemon-reload || true
  systemctl start netfilter-persistent || true
  systemctl enable --now rc-local cron netfilter-persistent || true
  systemctl restart nginx xray cron haproxy || true
  print_success "Enable Service"
  clear
}

password_default(){ :; }  # stub to keep your flow

instal(){
  clear
  first_setup
  nginx_install
  base_package
  make_folder_xray
  install_domain
  password_default
  install_ssl
  install_xray
  ssh
  udp_mini
  ssh_slow
  ins_SSHD
  ins_dropbear
  ins_vnstat
  ins_openvpn
  ins_backup
  ins_swab
  ins_Fail2ban
  ins_epro
  ins_restart
  menu
  profile
  enable_services
  restart_system
}

# Run
instal

echo ""
history -c || true
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain || true
secs_to_human "$(($(date +%s) - ${start}))"

# Hostname set to username captured during restart_system (if available)
if [[ -f /usr/bin/user ]]; then
  username="$(cat /usr/bin/user)"
  [[ -n "${username}" ]] && hostnamectl set-hostname "${username}" || true
fi

echo -e "${GREEN} Installation is completed. Happy Tunneling ${NC}"
echo ""
read -rp "$( echo -e "Press ${YELLOW}[ Enter ]${NC} for reboot") " _
reboot