#!/usr/bin/env bash
# Spider Store Unified Installer (Ubuntu 20/22/24+, Debian 10/11/12+)
set -euo pipefail

###########################
# Basic variables & repo
###########################
REPO="https://raw.githubusercontent.com/spider660/Lau_Op/main/"
start=$(date +%s)

###########################
# Colors
###########################
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
NC="\033[0m"
OK="${GREEN}  »${NC}"
ERROR="${RED}[ERROR]${NC}"
GRAY="\e[1;30m"

###########################
# Helper prints
###########################
print_ok() { echo -e "${OK} ${BLUE}$1${NC}"; }
print_install() {
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${YELLOW} » $1 ${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  sleep 1
}
print_error() { echo -e "${ERROR} $1"; }
print_success() {
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN} » $1${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  sleep 1
}

###########################
# Basic checks & banner
###########################
apt-get update -y
apt-get upgrade -y
apt-get install -y figlet curl wget sudo unzip tar socat lsof iproute2 || true
clear

typing_banner() {
  local text="$1"
  local color="$2"
  echo -e "${color}\e[1m"
  for (( i=0; i<${#text}; i++ )); do
    echo -ne "${text:i:1}"
    sleep 0.03
  done
  echo -e "${NC}"
}

echo -e "\e[92m$(figlet -f small -w 80 'WELCOME TO SPIDER STORE')\e[0m"
typing_banner "Programmer: SPIDER" "$GREEN"
typing_banner "©2024: STABLE EDITION" "$GREEN"
typing_banner "⚠️ ATTENTION!" "$RED"
typing_banner "This is the Original script; any cloned version of my script is pirated. Don't install it, it is bugged. t.me/spid_3r for more info." "$BLUE"
typing_banner "Happy Tunneling!" "$YELLOW"

###########################
# OS detection + IP
###########################
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID=$ID
  OS_VER=$VERSION_ID
  PRETTY_NAME=${PRETTY_NAME:-"$OS_ID $OS_VER"}
else
  print_error "Unable to detect OS. Exiting."
  exit 1
fi

IP=$(curl -sS ipv4.icanhazip.com || true)

if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
  echo -e "${ERROR} Your OS (${PRETTY_NAME}) is not supported."
  exit 1
fi

echo -e "${GREEN}  » Your OS Is Supported ( ${PRETTY_NAME} )${NC}"

if [[ -z "$IP" ]]; then
  echo -e "${ERROR} IP Address not detected. Exiting."
  exit 1
else
  echo -e "${GREEN}  » IP Address: ${IP}${NC}"
fi

ALLOWED_IPS_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/Database"
if curl -s "$ALLOWED_IPS_URL" | grep -Ev '^###' | grep -q "$IP"; then
  echo -e "${GREEN}  » Your IP is registered for installation.${NC}"
else
  echo -e "${ERROR}${GRAY} COULD NOT FIND ${NC} ${YELLOW}${IP}${NC} ${GRAY}IN THE DATABASE! INSTALLATION IS ABORTED.${NC}"
  exit 1
fi

read -p "$( echo -e "Press ${GREEN}[ Enter ]${NC} to start installation") "

if [[ "$EUID" -ne 0 ]]; then
  echo "You need to run this script as root"
  exit 1
fi

if [[ "$(systemd-detect-virt 2>/dev/null || echo '')" == "openvz" ]]; then
  echo "OpenVZ is not supported"
  exit 1
fi

###########################
# Version-aware dependencies
###########################
print_install "Installing base dependencies for $PRETTY_NAME"

# ensure basic tools
apt-get update -y
apt-get install -y lsb-release gnupg2 ca-certificates apt-transport-https software-properties-common || true

case "$OS_ID" in
  ubuntu)
    # safe defaults for common Ubuntu versions
    apt-get install -y ruby figlet wget curl unzip zip socat || true
    ;;
  debian)
    apt-get install -y ruby figlet wget curl unzip zip socat gnupg2 || true
    ;;
esac

# common extras
apt-get install -y sudo net-tools iputils-ping jq cron bash-completion || true

###########################
# Utility functions
###########################
secs_to_human() {
  echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "Root user detected, starting installation process"
  else
    print_error "The current user is not root. Switch to root and run the script again."
    exit 1
  fi
}

is_root

###########################
# Create Xray directories etc.
###########################
print_install "Create xray directory"

mkdir -p /etc/xray /var/log/xray /var/lib/kyt /usr/bin/xray /var/www/html
curl -s ifconfig.me > /etc/xray/ipvps || true
touch /etc/xray/domain
touch /var/log/xray/access.log /var/log/xray/error.log || true
chown -R www-data:www-data /var/log/xray || true
chmod +x /var/log/xray 2>/dev/null || true

# RAM calculation
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
  case $a in
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
    "Shmem") ((mem_used+=${b/kB})) ;;
    "MemFree" | "Buffers" | "Cached" | "SReclaimable") ((mem_used-=${b/kB})) ;;
  esac
done < /proc/meminfo || true

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/ || echo "$IP")

###########################
# first_setup: timezone, deps for haproxy/nginx
###########################
function first_setup() {
  timedatectl set-timezone Africa/Nairobi || true

  # Preconfigure iptables-persistent
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  print_success "Directory Xray"

  apt-get install -y lsb-release software-properties-common curl gnupg2 || true

  if [[ "$OS_ID" == "ubuntu" ]]; then
    apt-get update -y
    # add PPA for haproxy (best-effort, safe)
    add-apt-repository -y ppa:vbernat/haproxy-2.8 || true
    apt-get update -y
    apt-get install -y haproxy nginx || true
  elif [[ "$OS_ID" == "debian" ]]; then
    apt-get update -y
    curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || true
    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -cs)-backports main" | tee /etc/apt/sources.list.d/haproxy.list || true
    apt-get update -y
    apt-get install -y haproxy nginx || true
  fi
}

###########################
# nginx install function
###########################
function nginx_install() {
  print_install "Setup nginx For OS: $OS_Name"
  apt-get install -y nginx || true
}

###########################
# base_package
###########################
function base_package() {
  clear
  print_install "Installing the Required Packages"

  apt-get update -y
  apt-get install -y zip pwgen openssl netcat socat cron bash-completion figlet || true

  apt-get upgrade -y
  apt-get dist-upgrade -y || true

  # Chrony / ntp handling
  if systemctl list-unit-files | grep -qw chronyd.service; then
    systemctl enable chronyd || true
    systemctl restart chronyd || true
    chronyc sourcestats -v 2>/dev/null || true
    chronyc tracking -v 2>/dev/null || true
  else
    apt-get install -y ntpdate || true
    ntpdate pool.ntp.org || true
  fi

  apt-get purge -y exim4 ufw firewalld || true
  apt-get autoremove -y || true
  apt-get clean || true

  apt-get install -y --no-install-recommends software-properties-common || true

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
    libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make \
    libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
    sed dirmngr libxml-parser-perl build-essential gcc g++ python3 htop lsof tar wget curl \
    ruby zip unzip p7zip-full python3-pip libc6 util-linux msmtp-mta ca-certificates \
    bsd-mailx iptables iptables-persistent netfilter-persistent net-tools \
    openssl ca-certificates gnupg gnupg2 lsb-release shc cmake git screen socat xz-utils \
    apt-transport-https dnsutils jq openvpn easy-rsa || true

  print_success "Required Packages Installed"
}

###########################
# Domain selection
###########################
function install_domain() {
  clear
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[1;32mPlease Select a Domain Type Below \e[0m"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[1;32m1)\e[0m Use Your Own Domain (Recommended)"
  echo -e " \e[1;32m2)\e[0m Use Random Domain"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  read -p " Please select 1-2 or any other key (Random) : " host
  echo ""
  if [[ $host == "1" ]]; then
    read -p " Input Domain : " host1
    echo "IP=" >> /var/lib/kyt/ipvps.conf || true
    echo "$host1" > /etc/xray/domain || true
    echo "$host1" > /root/domain || true
  elif [[ $host == "2" ]]; then
    wget --no-check-certificate "${REPO}ubuntu/cf.sh" -O /root/cf.sh || true
    chmod +x /root/cf.sh || true
    /root/cf.sh || true
    rm -f /root/cf.sh || true
    clear
  else
    print_install "Random Subdomain/Domain is Used"
    clear
  fi
}

###########################
# restart_system: notif via telegram (best-effort)
###########################
function restart_system() {
  MYIP=$(curl -sS ipv4.icanhazip.com || echo "$IP")
  clear
  print_install "Sending install notification (best-effort)"
  IZINSC_URL="${REPO}keygen"
  rm -f /usr/bin/user /usr/bin/e || true
  username=$(curl -s "$IZINSC_URL" | grep "$MYIP" | awk '{print $2}' || true)
  echo "$username" > /usr/bin/user || true
  expx=$(curl -s "$IZINSC_URL" | grep "$MYIP" | awk '{print $3}' || true)
  echo "$expx" > /usr/bin/e || true

  username=$(cat /usr/bin/user 2>/dev/null || echo "unknown")
  oid=$(cat /usr/bin/ver 2>/dev/null || echo "N/A")
  exp=$(cat /usr/bin/e 2>/dev/null || echo "N/A")
  domain=$(cat /root/domain 2>/dev/null || echo "N/A")
  DATE=$(date +'%Y-%m-%d')
  ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 || true)
  TIMEZONE=$(date +"%H:%M:%S")
  TEXT="<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>WELCOME TO SPIDER STORE</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>DATE     :</code><code>$DATE</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>WELCOME TO SPIDER STORE</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<i>Automatic Notifications From Github</i>"
  # Telegram send (best-effort) - note: token/chat id left as in your original
  CHATID="5459129686"
  KEY="6623979288:AAHeqh3tO_pZ3UVRz_bIN1qgyQuDPq0q0SI"
  URL="https://api.telegram.org/bot$KEY/sendMessage"
  curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "$URL" >/dev/null 2>&1 || true
}

###########################
# SSL install (acme.sh)
###########################
function install_ssl() {
  clear
  print_install "Installing SSL On Domain"
  rm -rf /etc/xray/xray.key /etc/xray/xray.crt || true
  domain=$(cat /root/domain 2>/dev/null || echo "")
  STOPWEBSERVER=$(lsof -t -i:80 || true)

  rm -rf /root/.acme.sh
  mkdir -p /root/.acme.sh
  curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh || true
  chmod +x /root/.acme.sh/acme.sh || true
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade || true
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt || true

  # stop known webservers if needed
  if [[ -n "$STOPWEBSERVER" ]]; then
    systemctl stop "$STOPWEBSERVER" 2>/dev/null || true
  fi
  systemctl stop nginx 2>/dev/null || true

  if [[ -n "$domain" ]]; then
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 || true
    /root/.acme.sh/acme.sh --installcert -d "$domain" \
      --fullchainpath /etc/xray/xray.crt \
      --keypath /etc/xray/xray.key --ecc || true
    chmod 644 /etc/xray/xray.key || true
    chmod 644 /etc/xray/xray.crt || true
    print_success "SSL Certificate"
  else
    print_error "No domain found; skipping SSL issuance"
  fi
}

###########################
# make_folder_xray
###########################
function make_folder_xray() {
  rm -rf /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
         /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db \
         /etc/user-create/user.log || true

  mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
  mkdir -p /usr/bin/xray /var/log/xray /var/www/html
  mkdir -p /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip
  mkdir -p /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh
  mkdir -p /etc/user-create

  touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log || true
  touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db || true

  echo "& plugin Account" >> /etc/vmess/.vmess.db || true
  echo "& plugin Account" >> /etc/vless/.vless.db || true
  echo "& plugin Account" >> /etc/trojan/.trojan.db || true
  echo "& plugin Account" >> /etc/shadowsocks/.shadowsocks.db || true
  echo "& plugin Account" >> /etc/ssh/.ssh.db || true
  echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log || true
}

###########################
# install_xray
###########################
function install_xray() {
  clear
  print_install "Core Xray Latest Version"

  domainSock_dir="/run/xray"
  mkdir -p "$domainSock_dir" || true
  chown www-data:www-data "$domainSock_dir" || true

  latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases \
    | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1 || true)

  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version" || true

  wget -q -O /etc/xray/config.json "${REPO}ubuntu/config.json" || true
  wget -q -O /etc/systemd/system/runn.service "${REPO}ubuntu/runn.service" || true

  domain=$(cat /etc/xray/domain 2>/dev/null || echo "undefined")
  IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo "undefined")

  print_success "Core Xray Latest Version"
  clear
}

###########################
# Packet config (haproxy/nginx)
###########################
curl -s ipinfo.io/city | tee /etc/xray/city >/dev/null 2>&1 || true
curl -s ipinfo.io/org | cut -d " " -f 2-10 | tee /etc/xray/isp >/dev/null 2>&1 || true

print_install "Installing Packet Configuration"
wget -q -O /etc/haproxy/haproxy.cfg "${REPO}ubuntu/haproxy.cfg" || true
wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}ubuntu/xray.conf" || true

domain=$(cat /etc/xray/domain 2>/dev/null || echo "example.com")
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg || true
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf || true

curl -s "${REPO}ubuntu/nginx.conf" > /etc/nginx/nginx.conf || true
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1 || true

chmod +x /etc/systemd/system/runn.service 2>/dev/null || true
rm -rf /etc/systemd/system/xray.service.d 2>/dev/null || true

cat > /etc/systemd/system/xray.service <<'EOF'
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
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

print_success "Configuration Packet"

###########################
# ssh password + keyboard conf
###########################
function ssh() {
  clear
  print_install "Installing Password SSH"
  wget -q -O /etc/pam.d/common-password "${REPO}ubuntu/password" || true
  chmod 644 /etc/pam.d/common-password || true

  if command -v dpkg-reconfigure >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration || true
  fi

  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string us" || true
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English" || true
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105" || true
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC" || true
  debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English" || true

  # rc.local + disable ipv6 setup (keeps compatibility)
  cat > /etc/systemd/system/rc-local.service <<'UNIT'
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
After=network.target
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT

  cat > /etc/rc.local <<'RC'
#!/bin/bash
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
RC

  chmod +x /etc/rc.local || true
  systemctl daemon-reload || true
  systemctl enable rc-local.service >/dev/null 2>&1 || true
  systemctl start rc-local.service >/dev/null 2>&1 || true

  ln -fs /usr/share/zoneinfo/Africa/Nairobi /etc/localtime || true
  sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true

  print_success "Password SSH"
}

###########################
# udp-mini, slow dns, dropbear, vnstat, openvpn, backup, swap, fail2ban, epro
###########################
function udp_mini() {
  clear
  print_install "Installing Service Limit IP & Quota"
  wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/fv-tunnel -O /tmp/fv-tunnel && chmod +x /tmp/fv-tunnel && /tmp/fv-tunnel || true
  rm -f /tmp/fv-tunnel || true
  mkdir -p /usr/local/kyt/
  wget -q -O /usr/local/kyt/udp-mini "${REPO}ubuntu/udp-mini" || true
  chmod +x /usr/local/kyt/udp-mini || true

  for i in 1 2 3; do
    wget -q -O /etc/systemd/system/udp-mini-${i}.service "${REPO}ubuntu/udp-mini-${i}.service" || true
    systemctl disable udp-mini-${i} 2>/dev/null || true
    systemctl stop udp-mini-${i} 2>/dev/null || true
    systemctl enable udp-mini-${i} 2>/dev/null || true
    systemctl start udp-mini-${i} 2>/dev/null || true
  done

  print_success "Limit IP Service"
}

function ssh_slow() {
  clear
  print_install "Installing the SlowDNS Server module"
  if wget -q -O /tmp/nameserver "${REPO}ubuntu/nameserver"; then
    chmod +x /tmp/nameserver
    if bash /tmp/nameserver | tee /root/install.log; then
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

function ins_SSHD() {
  clear
  print_install "Installing SSHD"
  wget -q -O /etc/ssh/sshd_config "${REPO}ubuntu/sshd" || true
  chmod 600 /etc/ssh/sshd_config || true
  systemctl restart ssh || true
  systemctl status ssh --no-pager || true
  print_success "SSHD"
}

function ins_dropbear() {
  clear
  print_install "Installing Dropbear"
  apt-get install -y dropbear >/dev/null 2>&1 || true
  wget -q -O /etc/default/dropbear "${REPO}ubuntu/dropbear.conf" || true
  chmod 644 /etc/default/dropbear || true
  systemctl restart dropbear || true
  systemctl status dropbear --no-pager || true
  print_success "Dropbear"
}

function ins_vnstat() {
  clear
  print_install "Installing Vnstat"
  apt-get install -y vnstat libsqlite3-dev > /dev/null 2>&1 || true
  systemctl restart vnstat 2>/dev/null || true

  # Build vnStat 2.8 if required
  if [ ! -f /usr/bin/vnstat ] || (vnstat --version 2>/dev/null | grep -q '2.8' >/dev/null 2>&1); then
    wget -q https://humdi.net/vnstat/vnstat-2.8.tar.gz -O /tmp/vnstat-2.8.tar.gz || true
    tar zxvf /tmp/vnstat-2.8.tar.gz -C /tmp || true
    if [ -d /tmp/vnstat-2.8 ]; then
      pushd /tmp/vnstat-2.8 >/dev/null 2>&1 || true
      ./configure --prefix=/usr --sysconfdir=/etc && make && make install || true
      popd >/dev/null 2>&1 || true
    fi
    rm -f /tmp/vnstat-2.8.tar.gz
    rm -rf /tmp/vnstat-2.8
  fi

  if [[ -z "${NET:-}" ]]; then
    NET=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1 || echo "eth0")
  fi

  vnstat -u -i "$NET" >/dev/null 2>&1 || true
  sed -i "s/Interface \"eth0\"/Interface \"${NET}\"/g" /etc/vnstat.conf || true
  chown vnstat:vnstat /var/lib/vnstat -R || true
  systemctl enable vnstat || true
  systemctl restart vnstat || true
  systemctl status vnstat --no-pager || true
  print_success "Vnstat"
}

function ins_openvpn() {
  clear
  print_install "Installing OpenVPN"
  wget -q -O /tmp/openvpn_installer "${REPO}ubuntu/openvpn" || true
  chmod +x /tmp/openvpn_installer || true
  /tmp/openvpn_installer || true
  systemctl restart openvpn || true
  print_success "OpenVPN"
}

function ins_backup() {
  clear
  print_install "Installing Backup Server"
  apt-get install -y rclone || true
  mkdir -p /root/.config/rclone
  wget -q -O /root/.config/rclone/rclone.conf "${REPO}ubuntu/rclone.conf" || true

  cd /tmp || true
  if git clone https://github.com/magnific0/wondershaper.git >/dev/null 2>&1; then
    cd wondershaper || true
    make install >/dev/null 2>&1 || true
    cd /tmp || true
    rm -rf /tmp/wondershaper || true
  fi

  echo > /home/limit || true
  apt-get install -y msmtp-mta ca-certificates bsd-mailx || true

  cat >/etc/msmtprc <<'MSMTP'
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
MSMTP

  chown -R www-data:www-data /etc/msmtprc || true
  wget -q -O /etc/ipserver "${REPO}ubuntu/ipserver" && bash /etc/ipserver || true
  print_success "Backup Server"
}

function ins_swab() {
  clear
  print_install "Installing Swap 1 G"
  gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*\"v(.*)\".*/\1/' | head -n 1 || true)"
  if [[ -n "$gotop_latest" ]]; then
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb || true
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1 || true
    rm -f /tmp/gotop.deb || true
  fi

  if ! swapon --show | grep -q "/swapfile"; then
    dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none || true
    mkswap /swapfile || true
    chown root:root /swapfile || true
    chmod 0600 /swapfile || true
    swapon /swapfile || true
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi

  chronyd -q 'server 0.id.pool.ntp.org iburst' 2>/dev/null || true
  chronyc sourcestats -v 2>/dev/null || true
  chronyc tracking -v 2>/dev/null || true

  wget -q "${REPO}ubuntu/bbr.sh" -O /tmp/bbr.sh && chmod +x /tmp/bbr.sh && /tmp/bbr.sh || true
  print_success "Swap 1 G"
}

function ins_Fail2ban() {
  clear
  print_install "Installing Fail2ban"
  apt-get install -y fail2ban >/dev/null 2>&1 || true
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  systemctl status fail2ban --no-pager >/dev/null 2>&1 || true

  if [ -d '/usr/local/ddos' ]; then
    echo; echo; echo "Please un-install the previous version first"
    exit 0
  else
    mkdir -p /usr/local/ddos || true
  fi

  grep -qxF 'Banner /etc/kyt.txt' /etc/ssh/sshd_config || echo 'Banner /etc/kyt.txt' >> /etc/ssh/sshd_config || true
  sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear 2>/dev/null || true
  wget -q -O /etc/kyt.txt "${REPO}ubuntu/issue.net" || true
  print_success "Fail2ban"
}

function ins_epro() {
  clear
  print_install "Installing ePro WebSocket Proxy"
  wget -q -O /usr/bin/ws "${REPO}ubuntu/ws" >/dev/null 2>&1 || true
  wget -q -O /usr/bin/tun.conf "${REPO}ubuntu/tun.conf" >/dev/null 2>&1 || true
  wget -q -O /etc/systemd/system/ws.service "${REPO}ubuntu/ws.service" >/dev/null 2>&1 || true
  chmod +x /usr/bin/ws || true
  chmod 644 /usr/bin/tun.conf || true

  systemctl disable ws 2>/dev/null || true
  systemctl stop ws 2>/dev/null || true
  systemctl enable ws 2>/dev/null || true
  systemctl start ws 2>/dev/null || true
  systemctl restart ws 2>/dev/null || true

  wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1 || true
  wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1 || true
  wget -q -O /usr/sbin/ftvpn "${REPO}ubuntu/ftvpn" >/dev/null 2>&1 || true
  chmod +x /usr/sbin/ftvpn || true

  for rule in "get_peers" "announce_peer" "find_node" "BitTorrent" "BitTorrent protocol" "peer_id=" ".torrent" "announce.php?passkey=" "torrent" "announce" "info_hash"; do
    iptables -A FORWARD -m string --string "$rule" --algo bm -j DROP || true
  done

  iptables-save > /etc/iptables.up.rules || true
  iptables-restore -t < /etc/iptables.up.rules || true
  netfilter-persistent save >/dev/null 2>&1 || true
  netfilter-persistent reload >/dev/null 2>&1 || true
  apt-get autoclean -y >/dev/null 2>&1 || true
  apt-get autoremove -y >/dev/null 2>&1 || true
  print_success "ePro WebSocket Proxy installed successfully"
}

###########################
# Restart / menu / profile / enable
###########################
function ins_restart(){
  clear
  print_install "Restarting All Services"

  systemctl restart nginx || /etc/init.d/nginx restart || true
  systemctl restart openvpn || /etc/init.d/openvpn restart || true
  systemctl restart ssh || /etc/init.d/ssh restart || true
  systemctl restart dropbear || /etc/init.d/dropbear restart || true
  systemctl restart fail2ban || /etc/init.d/fail2ban restart || true
  systemctl restart vnstat || /etc/init.d/vnstat restart || true
  systemctl restart haproxy || true
  systemctl restart cron || /etc/init.d/cron restart || true

  systemctl daemon-reload || true
  systemctl enable --now netfilter-persistent || true
  systemctl enable --now nginx || true
  systemctl enable --now xray || true
  systemctl enable --now rc-local || true
  systemctl enable --now dropbear || true
  systemctl enable --now openvpn || true
  systemctl enable --now cron || true
  systemctl enable --now haproxy || true
  systemctl enable --now ws || true
  systemctl enable --now fail2ban || true

  history -c || true
  echo "unset HISTFILE" >> /etc/profile || true
  rm -f /root/openvpn /root/key.pem /root/cert.pem || true
  print_success "All Services Restarted"
}

function menu(){
  clear
  print_install "Installing Menu Packet"
  wget -q "${REPO}ubuntu/menu.zip" || true
  unzip -o menu.zip || true
  chmod +x menu/* || true
  mv -f menu/* /usr/local/sbin || true
  rm -rf menu menu.zip || true
  print_success "Menu Packet"
}

function profile(){
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

  cat >/etc/cron.d/xp_all <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

  cat >/etc/cron.d/logclean <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

  chmod 644 /root/.profile || true

  cat >/etc/cron.d/daily_reboot <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

  cat >/etc/cron.d/limit_ip <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

  cat >/etc/cron.d/limit_ip2 <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

  echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx || true
  echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray || true

  systemctl restart cron || true

  echo "5" > /home/daily_reboot || true

  cat >/etc/systemd/system/rc-local.service <<'EOF'
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

  echo "/bin/false" >>/etc/shells || true
  echo "/usr/sbin/nologin" >>/etc/shells || true

  cat >/etc/rc.local <<'EOF'
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent || true
exit 0
EOF
  chmod +x /etc/rc.local || true

  AUTOREB=$(cat /home/daily_reboot 2>/dev/null || echo 5)
  SETT=11
  if [ "$AUTOREB" -gt "$SETT" ]; then
    TIME_DATE="PM"
  else
    TIME_DATE="AM"
  fi

  print_success "Menu Packet"
}

function enable_services(){
  clear
  print_install "Enable Services"
  systemctl daemon-reload || true
  systemctl start netfilter-persistent || true
  systemctl enable --now rc-local || true
  systemctl enable --now cron || true
  systemctl enable --now netfilter-persistent || true
  systemctl restart nginx xray cron haproxy || true
  print_success "Services Enabled"
}

###########################
# Installer sequence & cleanup
###########################
function instal(){
  clear
  first_setup
  nginx_install
  base_package
  make_folder_xray
  install_domain
  # password_default function referenced in original -- keep as a placeholder
  if declare -f password_default >/dev/null 2>&1; then
    password_default || true
  fi
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

instal

# Cleanup
echo ""
history -c || true
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain || true
secs_to_human "$(($(date +%s) - ${start}))"
# set hostname if username set
if [[ -n "${username:-}" ]]; then
  hostnamectl set-hostname "$username" || true
fi

echo -e "${GREEN}Installation is completed. Happy Tunneling!${NC}"
read -p "$( echo -e "Press ${YELLOW}[ Enter ]${NC} to reboot (or Ctrl-C to cancel)" ) " || true
reboot || true
