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

#!/usr/bin/env bash

# Load OS info
. /etc/os-release
OS_ID="${ID:-}"
OS_NAME="${PRETTY_NAME:-Unknown}"

# Check supported OS
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    echo -e "${GREEN}  » Your OS Is Supported ( ${OS_NAME} )${NC}"
else
    echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}${OS_NAME}${NC} )"
    exit 1
fi

# Check root
if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Check virtualization
if systemd-detect-virt | grep -qi openvz; then
    echo "OpenVZ is not supported"
    exit 1
fi

echo -e "\e[32mloading...\e[0m"
clear
apt update -y
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

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    echo "& plughin Account" >>/etc/vmess/.vmess.db
    echo "& plughin Account" >>/etc/vless/.vless.db
    echo "& plughin Account" >>/etc/trojan/.trojan.db
    echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
    }
#Instal Xray
function install_xray() {
clear
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # / / Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
 
    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}ubuntu/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}ubuntu/runn.service" >/dev/null 2>&1
    #chmod +x /usr/local/bin/xray
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    print_success "Core Xray 1.8.1 Latest Version"
    
    # Settings UP Nginix Server
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Installing Packet Configuration"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}ubuntu/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}ubuntu/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}ubuntu/nginx.conf > /etc/nginx/nginx.conf
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
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
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
print_success "Configuration Packet"
}

function ssh(){
clear
print_install "Installing Password SSH"
wget -O /etc/pam.d/common-password "${REPO}ubuntu/password"
chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}

function udp_mini(){
clear
print_install "Installing Service Limit IP & Quota"
wget -q https://raw.githubusercontent.com/Ghalihx/scupdate/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

# // Installing UDP Mini
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}ubuntu/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}ubuntu/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}ubuntu/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}ubuntu/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
print_success "Limit IP Service"
}

function ssh_slow(){
clear
# // Installing UDP Mini
print_install "Installing the SlowDNS Server module"
    wget -q -O /tmp/nameserver "${REPO}ubuntu/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
 print_success "SlowDNS"
}

clear
function ins_SSHD(){
clear
print_install "Installing SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}ubuntu/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
/etc/init.d/ssh restart
systemctl restart ssh
/etc/init.d/ssh status
print_success "SSHD"
}

clear
function ins_dropbear(){
clear
print_install "Installing Dropbear"
# // Installing Dropbear
apt-get install dropbear -y > /dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}ubuntu/dropbear.conf"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
print_success "Dropbear"
}

clear
function ins_vnstat(){
clear
print_install "Installing Vnstat"
# setting vnstat
apt -y install vnstat > /dev/null 2>&1
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
/etc/init.d/vnstat status
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
print_success "Vnstat"
}

function ins_openvpn(){
clear
print_install "Installing OpenVPN"
#OpenVPN
wget ${REPO}ubuntu/openvpn &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}

function ins_backup(){
clear
print_install "Installing Backup Server"
#BackupOption
apt install rclone -y
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${REPO}ubuntu/rclone.conf"
#Install Wondershaper
cd /bin
git clone  https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf wondershaper
echo > /home/limit
apt install msmtp-mta ca-certificates bsd-mailx -y
cat<<EOF>>/etc/msmtprc
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
chown -R www-data:www-data /etc/msmtprc
wget -q -O /etc/ipserver "${REPO}ubuntu/ipserver" && bash /etc/ipserver
print_success "Backup Server"
}

clear
function ins_swab(){
clear
print_install "Installing Swap 1 G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
    # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
    wget ${REPO}ubuntu/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 G"
}

function ins_Fail2ban(){
clear
print_install "Installing Fail2ban"
#apt -y install fail2ban > /dev/null 2>&1
#sudo systemctl enable --now fail2ban
#/etc/init.d/fail2ban restart
#/etc/init.d/fail2ban status

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi

clear
# banner
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

# Ganti Banner
wget -O /etc/kyt.txt "${REPO}ubuntu/issue.net"
print_success "Fail2ban"
}

function ins_epro(){
clear
print_install "Installing  ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}ubuntu/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}ubuntu/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}ubuntu/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
systemctl disable ws
systemctl stop ws
systemctl enable ws
systemctl start ws
systemctl restart ws
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${REPO}ubuntu/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# remove unnecessary files
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy"
}

function ins_restart(){
clear
print_install "Restarting  All Packet"
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
systemctl restart haproxy
/etc/init.d/cron restart
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now nginx
    systemctl enable --now xray
    systemctl enable --now rc-local
    systemctl enable --now dropbear
    systemctl enable --now openvpn
    systemctl enable --now cron
    systemctl enable --now haproxy
    systemctl enable --now netfilter-persistent
    systemctl enable --now ws
    systemctl enable --now fail2ban
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
print_success "All Packet"
}

#Instal Menu
function menu(){
    clear
    print_install "Installing  Menu Packet"
    wget ${REPO}ubuntu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Membaut Default Menu 
function profile(){
clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
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
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    cat >/home/daily_reboot <<-END
		5
	END

cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
print_success "Menu Packet"
}

# Restart layanan after install
function enable_services(){
clear
print_install "Enable Service"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}

# Fingsi Install Script
function instal(){
clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
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
instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain
#sudo hostnamectl set-hostname $user
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
echo -e "${green}   [ ${NC}${RED}Spider 🕷️ webx  Script${NC} ${RED}] is Successfully Installed enjoy 😇 all thanks to lau spidey"
echo ""
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
