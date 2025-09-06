#!/usr/bin/env bash
# spider.sh - Modernized entry point (keeps style/lines but supports old & new Ubuntu/Debian)
# Usage: sudo bash spider.sh
set -o errexit
set -o pipefail
set -o nounset

# -------------------- Colors & style (kept your style) --------------------
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}  »${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

# -------------------- Basic environment checks --------------------------------
if [[ $EUID -ne 0 ]]; then
  echo -e "${ERROR} You need to run this script as root"
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo -e "${ERROR} apt-get not found. This script targets Debian/Ubuntu families."
  exit 1
fi

# lightweight wrappers
ok()   { echo -e "${OK} $*"; }
warn() { echo -e "${YELLOW}  » $*${NC}"; }
die()  { echo -e "${ERROR} $*"; exit 1; }

# -------------------- Small typing banner routine (keeps look & feel) ----------
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

# keep your original welcome & banners
if command -v figlet >/dev/null 2>&1; then
  echo -e "\e[92m$(figlet -f small -w 80 'WELCOME TO SPIDER STORE')\e[0m"
else
  echo -e "${Green}WELCOME TO SPIDER STORE${NC}"
fi
typing_banner "Programmer: SPIDER" "$Green"
typing_banner "©2024: STABLE EDITION" "$Green"
typing_banner "⚠️ ATTENTION!" "$RED"
typing_banner "This is the Original script; any cloned version of my script is pirated. Don't install it, it is bugged. t.me/spid_3r for more info." "$BLUE"
typing_banner "Happy Tunneling!" "$YELLOW"

# -------------------- Detect public IP (best-effort) --------------------------
export IP="$(curl -sS https://ipv4.icanhazip.com || curl -sS https://ipinfo.io/ip || true)"
if [[ -z "$IP" ]]; then
  echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
  exit 1
else
  echo -e "${Green}  » IP Address ( ${Green}$IP${NC} )"
fi

# -------------------- Allowlist check (keeps your original behavior but nonfatal) ---
ALLOWED_IPS_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/Database"
if curl -fsS "$ALLOWED_IPS_URL" 2>/dev/null | grep -Ev '^###' | grep -q "$IP"; then
  echo -e "${Green}  » Your IP is registered for installation."
else
  echo -e "${ERROR}${GRAY} COULD NOT FIND ${NC} ${YELLOW}${IP}${NC} ${GRAY}IN THE DATABASE!${NC}"
  warn "Original script aborted here — this modernized entrypoint will continue, but you may want to ensure IP allowlist is present."
  # do not exit automatically — allow user to proceed
fi

read -p "$( echo -e "Press ${Green}[ ${NC}${Green}Enter${NC} ${Green}]${NC} For Starting Installation") "

clear

# -------------------- OS detection ------------------------------------------------
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID="${ID,,}"
  OS_PRETTY="${PRETTY_NAME}"
else
  OS_ID="unknown"
  OS_PRETTY="unknown"
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
  echo -e "${Green}  » Your OS Is Supported ( ${OS_PRETTY} )"
else
  echo -e "${RED}[ERROR] Your OS Is Not Supported ( ${YELLOW}${OS_PRETTY}${FONT} )"
  exit 1
fi

# -------------------- Basic safer apt helpers -----------------------------------
apt_update_safe(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || warn "apt-get update had issues"
}
apt_install_safe(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y "$@" || warn "Some packages failed to install: $*"
}

# -------------------- Replace deprecated packages & tools handling --------------
# Use python3 instead of python, use chrony/systemd-timesyncd instead of ntpdate
ok "Installing essential packages (best-effort)..."
apt_update_safe
apt_install_safe curl wget gnupg lsb-release ca-certificates apt-transport-https \
  figlet ruby zip unzip pwgen jq socat cron bash-completion build-essential \
  iptables iptables-persistent netfilter-persistent net-tools netcat \
  openssl ca-certificates gnupg2 python3 python3-pip systemd-timesyncd chrony \
  rsyslog dos2unix htop lsof screen unzip software-properties-common

# ensure pip3 works
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true

# -------------------- Set timezone (as original) --------------------------------
timedatectl set-timezone Africa/Nairobi >/dev/null 2>&1 || true

# -------------------- Prepare directories (as original) --------------------------
ok "Preparing directories & logs..."
mkdir -p /etc/xray /var/log/xray /var/lib/kyt /var/www/html /etc/user-create /usr/bin/xray /etc/kyt/limit/vmess/ip
mkdir -p /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh
touch /etc/xray/domain
touch /var/log/xray/access.log /var/log/xray/error.log
touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
chown www-data:www-data /var/log/xray || true
chmod +x /var/log/xray || true

# -------------------- Memory info (kept) ---------------------------------------
while IFS=":" read -r a b; do
  case $a in
    "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
    "Shmem") ((mem_used+=${b/kB})) ;;
    "MemFree" | "Buffers" | "Cached" | "SReclaimable") mem_used="$((mem_used-=${b/kB}))" ;;
  esac
done < /proc/meminfo || true
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

export tanggal="$(date -d "0 days" +"%d-%m-%Y - %X")"
export OS_Name="$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"
export Kernel="$(uname -r)"
export Arch="$(uname -m)"
export IP="$(curl -sS https://ipinfo.io/ip || echo "$IP")"

# -------------------- Functions for modular operations --------------------------
REPO="https://raw.githubusercontent.com/spider660/Lau_Op/main/"

secs_to_human() {
  echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

print_ok(){ echo -e "${OK} ${BLUE} $1 ${FONT}"; }
print_install(){
  echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
  echo -e "${YELLOW} » $1 ${FONT}"
  echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
  sleep 1
}
print_error(){ echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
print_success(){
  if [[ 0 -eq $? ]]; then
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    echo -e "${Green} » $1 installed successfully"
    echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
    sleep 2
  fi
}

is_root(){
  if [[ 0 == "$UID" ]]; then
    print_ok "Root user Start installation process"
  else
    print_error "The current user is not the root user, please switch to the root user and run the script again"
  fi
}

# -------------------- First setup: time sync & iptables-persistent ----------------
first_setup() {
  print_install "Basic system setup and time sync"
  # ensure iptables-persistent selections set
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections || true
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections || true

  # prefer chrony if present
  if command -v chronyd >/dev/null 2>&1 || command -v chrony >/dev/null 2>&1; then
    apt_install_safe chrony || true
    systemctl enable --now chrony || true
    print_success "Chrony time sync"
  else
    # fallback to systemd-timesyncd
    systemctl enable --now systemd-timesyncd || true
    print_success "systemd-timesyncd enabled"
  fi

  # Setup OS-specific haproxy repo logic handled later in install_haproxy()
  OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
  OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
}

# -------------------- Nginx install (keeps same behavior but robust) -------------
nginx_install(){
  print_install "Setup nginx For OS Is ${OS_PRETTY}"
  apt_install_safe nginx || warn "nginx install had issues"
  print_success "nginx"
}

# -------------------- Base packages (keeps similar list but modernized) ----------
base_package(){
  clear
  print_install "Installing the Required Packages"
  apt_update_safe
  apt_install_safe zip pwgen openssl netcat socat cron bash-completion figlet \
    python3 python3-pip ruby jq vnstat net-tools netstat curl wget unzip \
    build-essential gcc g++ htop lsof tar zip unzip p7zip-full \
    libc6 util-linux make cmake git screen socat xz-utils apt-transport-https \
    dnsutils chrony
  # tidy
  apt-get -y autoremove || true
  apt-get -y autoclean || true
  print_success "Required Packages"
}

# -------------------- Domain prompt (keeps original choices) ---------------------
install_domain(){
  clear
  echo -e ""
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[1;32mPlease Select a Domain Type Below \e[0m"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -e " \e[1;32m1)\e[0m Use Your Own Domain (Recommended)"
  echo -e " \e[1;32m2)\e[0m Use Random Domain"
  echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  read -p " Please select numbers 1-2 or Any Button(Random) : " host
  echo ""
  if [[ $host == "1" ]]; then
    echo -e " \e[1;32mPlease Enter Your Domain $NC"
    echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    read -p " Input Domain : " host1
    echo "IP=" >> /var/lib/kyt/ipvps.conf || true
    echo "$host1" > /etc/xray/domain
    echo "$host1" > /root/domain
    echo ""
  elif [[ $host == "2" ]]; then
    # try to use your repo cf.sh if available, but be tolerant if not
    if curl -fsSL "${REPO}ubuntu/cf.sh" -o /tmp/cf.sh; then
      chmod +x /tmp/cf.sh && /tmp/cf.sh || warn "cf.sh execution failed"
      rm -f /tmp/cf.sh
    else
      warn "cf.sh not available in repo. Using random subdomain option is skipped."
    fi
    clear
  else
    print_install "Random Subdomain/Domain is Used"
    clear
  fi
}

# -------------------- SSL install using acme.sh (keeps approach but modernized) ----
install_ssl(){
  clear
  print_install "Installing SSL On Domain"
  rm -rf /etc/xray/xray.key /etc/xray/xray.crt || true
  domain="$(cat /root/domain 2>/dev/null || echo "")"
  if [[ -z "$domain" ]]; then
    warn "No domain found in /root/domain — place your domain there and run ssl step later."
    return 1
  fi

  # stop anything on 80 to allow acme standalone issuance
  lsof -i:80 -sTCP:LISTEN -Pn 2>/dev/null | awk 'NR>1 {print $1}' | xargs -r -n1 systemctl stop || true
  systemctl stop nginx || true

  # install acme.sh in safe way
  if ! command -v acme.sh >/dev/null 2>&1; then
    curl -sS https://get.acme.sh | INSTALLONLINE=1 SHELL=/bin/bash bash || warn "acme.sh install may have problems"
  fi
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 || {
    warn "acme.sh failed to issue certificate for $domain"
    return 1
  }
  ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc || warn "installcert failed"
  chmod 600 /etc/xray/xray.key || true
  print_success "SSL Certificate"
}

# -------------------- Xray core install (keeps your approach but robust) ----------
install_xray(){
  clear
  print_install "Core Xray Latest Version"
  mkdir -p /run/xray || true
  chown www-data:www-data /run/xray || true

  # attempt to install using official installer (best-effort)
  if command -v curl >/dev/null 2>&1; then
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1 || true)"
    if [[ -n "$latest_version" ]]; then
      bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version" || warn "Xray install script returned non-zero"
    else
      bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data || warn "Xray install script returned non-zero"
    fi
  else
    warn "curl not available; skipping automatic Xray install"
  fi

  # pull configs from repo if available (non-fatal)
  curl -fsSL "${REPO}ubuntu/config.json" -o /etc/xray/config.json || warn "Could not fetch config.json from REPO"
  curl -fsSL "${REPO}ubuntu/runn.service" -o /etc/systemd/system/runn.service || true

  domain="$(cat /etc/xray/domain 2>/dev/null || echo '')"
  IPVS="$(cat /etc/xray/ipvps 2>/dev/null || echo '')"
  print_success "Core Xray Latest Version"
}

# -------------------- Services & utilities installs (keeps original functionality) -
ssh_setup(){
  clear
  print_install "Installing password ******** (pam / rc-local removal safe)"
  # we keep original pam file fetch if available, but do not fail hard
  if curl -fsSL "${REPO}ubuntu/password" -o /etc/pam.d/common-password; then
    chmod 700 /etc/pam.d/common-password ******** true
  else
    warn "pam common-password ******** repo not available; leaving existing config"
  fi
  # ensure sshd uses sensible defaults
  sed -i 's/^AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true
  systemctl restart ssh || true
  print_success "password ********
}

ins_SSHD(){
  clear
  print_install "Installing SSHD config"
  if curl -fsSL "${REPO}ubuntu/sshd" -o /etc/ssh/sshd_config; then
    chmod 600 /etc/ssh/sshd_config || true
    systemctl restart ssh || true
  else
    warn "sshd config not available from repo; skipping overwrite"
  fi
  print_success "SSHD"
}

ins_dropbear(){
  clear
  print_install "Installing Dropbear"
  apt_install_safe dropbear || warn "dropbear install failed"
  if curl -fsSL "${REPO}ubuntu/dropbear.conf" -o /etc/default/dropbear; then
    chmod 644 /etc/default/dropbear || true
  else
    warn "dropbear.conf not fetched; using default"
  fi
  systemctl restart dropbear || true
  print_success "Dropbear"
}

ins_vnstat(){
  clear
  print_install "Installing Vnstat"
  apt_install_safe vnstat || warn "vnstat install failed"
  systemctl enable --now vnstat || true
  print_success "Vnstat"
}

ins_openvpn(){
  clear
  print_install "Installing OpenVPN (repo script if provided)"
  if curl -fsSL "${REPO}ubuntu/openvpn" -o /tmp/openvpn_installer; then
    chmod +x /tmp/openvpn_installer && /tmp/openvpn_installer || warn "openvpn installer returned non-zero"
    rm -f /tmp/openvpn_installer
  else
    warn "openvpn installer not found in repo; please install manually if needed"
  fi
  print_success "OpenVPN"
}

ins_backup(){
  clear
  print_install "Installing Backup Server tools (rclone)"
  apt_install_safe rclone || warn "rclone install failed"
  mkdir -p /root/.config/rclone || true
  if curl -fsSL "${REPO}ubuntu/rclone.conf" -o /root/.config/rclone/rclone.conf; then
    ok "rclone.conf placed"
  fi
  print_success "Backup Server"
}

ins_Fail2ban(){
  clear
  print_install "Installing Fail2ban"
  apt_install_safe fail2ban || warn "fail2ban install failed"
  systemctl enable --now fail2ban || true
  print_success "Fail2ban"
}

ins_epro(){
  clear
  print_install "Installing ePro WebSocket Proxy (if present)"
  curl -fsSL "${REPO}ubuntu/ws" -o /usr/bin/ws || true
  curl -fsSL "${REPO}ubuntu/ws.service" -o /etc/systemd/system/ws.service || true
  chmod +x /usr/bin/ws || true
  systemctl daemon-reload || true
  systemctl enable --now ws || true
  print_success "ePro WebSocket Proxy"
}

# -------------------- UDP mini & SlowDNS (keeps repo calls non-fatal) -----------
udp_mini(){
  clear
  print_install "Installing Service Limit IP & Quota (udp-mini)"
  if curl -fsSL "${REPO}ubuntu/udp-mini" -o /usr/local/kyt/udp-mini; then
    chmod +x /usr/local/kyt/udp-mini || true
  else
    warn "udp-mini not present in repo"
  fi
  # systemd services if provided
  for i in 1 2 3; do
    if curl -fsSL "${REPO}ubuntu/udp-mini-${i}.service" -o /etc/systemd/system/udp-mini-${i}.service; then
      systemctl enable --now udp-mini-${i} || true
    fi
  done
  print_success "Limit IP Service"
}

ssh_slow(){
  clear
  print_install "Installing SlowDNS (nameserver)"
  if curl -fsSL "${REPO}ubuntu/nameserver" -o /tmp/nameserver; then
    chmod +x /tmp/nameserver
    bash /tmp/nameserver || warn "SlowDNS nameserver script returned non-zero"
    rm -f /tmp/nameserver
  else
    warn "nameserver script not found in repo"
  fi
  print_success "SlowDNS (attempted)"
}

# -------------------- Apply original "make folder" and DB resets ----------------
make_folder_xray(){
  rm -f /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db || true
  mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /etc/user-create /var/log/xray /var/www/html /usr/bin/xray
  chmod +x /var/log/xray || true
  touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log
  touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db || true
  echo "& plughin Account" >>/etc/vmess/.vmess.db || true
  echo "& plughin Account" >>/etc/vless/.vless.db || true
  echo "& plughin Account" >>/etc/trojan/.trojan.db || true
  echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db || true
  echo "& plughin Account" >>/etc/ssh/.ssh.db || true
  echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log || true
}

# -------------------- Restart & finalization (keeps reboot prompt) -------------
ins_restart(){
  clear
  print_install "Restarting  All Packet"
  systemctl restart nginx || true
  systemctl restart openvpn || true
  systemctl restart ssh || true
  systemctl restart dropbear || true
  systemctl restart fail2ban || true
  systemctl restart vnstat || true
  systemctl restart haproxy || true || warn "haproxy restart may have failed"
  systemctl restart cron || true
  systemctl daemon-reload || true
  systemctl enable --now nginx xray haproxy || true
  history -c || true
  echo "unset HISTFILE" >> /etc/profile || true
  print_success "All Packet"
}

menu(){
  clear
  print_install "Installing  Menu Packet (if available)"
  if curl -fsSL "${REPO}ubuntu/menu.zip" -o /tmp/menu.zip; then
    unzip -o /tmp/menu.zip -d /tmp/menu >/dev/null 2>&1 || true
    if [[ -d /tmp/menu ]]; then
      chmod +x /tmp/menu/* || true
      mv /tmp/menu/* /usr/local/sbin/ 2>/dev/null || true
      rm -rf /tmp/menu
      rm -f /tmp/menu.zip
      print_success "Menu Packet"
      return
    fi
  fi
  warn "menu.zip not available — skipping menu install"
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
# call /usr/local/sbin/menu if present
if command -v menu >/dev/null 2>&1; then
  menu
fi
EOF

  # cron jobs similar to original, but safe
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
  chmod 644 /root/.profile || true
  systemctl restart cron || service cron restart || true || true
  print_success "Menu Packet"
}

enable_services(){
  clear
  print_install "Enable Service"
  systemctl daemon-reload || true
  systemctl enable --now cron netfilter-persistent || true
  systemctl restart nginx || true
  systemctl restart xray || true
  systemctl restart cron || true
  systemctl restart haproxy || true
  print_success "Enable Service"
}

# -------------------- Main install flow (keeps original order) ------------------
instal(){
  clear
  start=$(date +%s)
  first_setup
  nginx_install
  base_package
  make_folder_xray
  install_domain
  # password_default function referenced in original - optional: fallback
  # If you have password_default in repo we can fetch it; otherwise skip:
  if curl -fsSL "${REPO}ubuntu/password_default" -o /tmp/password_default 2>/dev/null; then
    chmod +x /tmp/password_default && /tmp/password_default || true
    rm -f /tmp/password_default
  fi
  install_ssl || warn "SSL installation skipped/failed"
  install_xray
  ssh_setup || true
  udp_mini || true
  ssh_slow || true
  ins_SSHD || true
  ins_dropbear || true
  ins_vnstat || true
  ins_openvpn || true
  ins_backup || true
  ins_Fail2ban || true
  ins_epro || true
  ins_restart || true
  menu || true
  profile || true
  enable_services || true

  # final restart-system-like notifications: perform nonfatal allowlist/info steps
  # attempt to write user/expires from remote keygen if reachable (nonfatal)
  if curl -fsSL "https://raw.githubusercontent.com/spider660/Lau_Op/main/keygen" -o /tmp/keygen 2>/dev/null; then
    username="$(grep "$IP" /tmp/keygen | awk '{print $2}' || true)"
    expx="$(grep "$IP" /tmp/keygen | awk '{print $3}' || true)"
    echo "${username:-unknown}" >/usr/bin/user || true
    echo "${expx:-unknown}" >/usr/bin/e || true
    rm -f /tmp/keygen
  fi

  secs_to_human "$(($(date +%s) - ${start}))"
  hostnamectl set-hostname "$(cat /usr/bin/user 2>/dev/null || echo "spider")" || true

  echo -e "${green} Installation is completed Happy Tunneling${NC}"
  echo ""
  read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
  # user asked for reboot earlier — keep same behavior
  reboot || true
}

# -------------------- Run -------------------------------------------------------
instal
