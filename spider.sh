#!/bin/bash
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
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y figlet
clear
# Lightweight typewriter effect (safer printing)
typing_banner() {
    local text="$1"
    local color="${2:-$NC}"
    printf "%b" "${color}\e[1m"
    local i
    for (( i=0; i<${#text}; i++ )); do
        printf "%s" "${text:i:1}"
        sleep 0.03
    done
    printf "%b\n" "${NC}"
}

# Simple spinner for long steps
spinner_start() {
    spin_pid=""
    ( while :; do for s in '/' '-' '\' '|' ; do printf "\r%s" "$s"; sleep 0.08; done; done ) & spin_pid=$!
    printf " "
}
spinner_stop() {
    if [ -n "${spin_pid:-}" ]; then
        kill "$spin_pid" >/dev/null 2>&1 || true
        wait "$spin_pid" 2>/dev/null || true
        unset spin_pid
        printf "\r"
    fi
}

# --- ADD: install animation (glitchy cyberpunk) ---
install_anim_loop() {
    local frames=( "◴" "◷" "◶" "◵" "▉" "▊" "▋" "▌" )
    local colors=( "${GREEN}" "${BLUE}" "${YELLOW}" "${RED}" )
    local clen=${#colors[@]}
    while true; do
        for f in "${frames[@]}"; do
            # create a short random binary "glitch" snippet
            local rand_bin="$(head -c 8 /dev/urandom 2>/dev/null | tr -dc '01' | head -c6)"
            local col="${colors[$((RANDOM % clen))]}"
            printf "\r%b %bINSTALLING...%b %s%b" "${col}" "${f}" "${NC}" "${rand_bin}" " "
            sleep 0.06
        done
    done
}

ANIM_PID=""
install_animation_start() {
    # don't start twice
    if [ -n "$ANIM_PID" ] && kill -0 "$ANIM_PID" 2>/dev/null; then
        return
    fi
    install_anim_loop >/dev/null 2>&1 & ANIM_PID=$!
    # ensure animation cleaned up on exit
    trap 'install_animation_stop' EXIT INT TERM
}

install_animation_stop() {
    if [ -n "$ANIM_PID" ]; then
        kill "$ANIM_PID" 2>/dev/null || true
        wait "$ANIM_PID" 2>/dev/null || true
        ANIM_PID=""
    fi
    # clear animation line
    printf "\r\033[K"
    # remove trap only if it points to our cleanup
    trap - EXIT INT TERM || true
}
# --- END ADD ---

# Small cyberpunk/hacker banner
hacker_banner() {
    clear
    echo -e "${Green}  ===============================================${NC}"
    echo -e "${BLUE}        ███ SPIDER STORE — CYBER INSTALL ███${NC}"
    echo -e "${Green}  ===============================================${NC}"
    glitch_write "Programmer: SPIDER" "$Green"
    glitch_write "©2024: STABLE EDITION" "$Green"
    glitch_write "⚠️ ATTENTION! Only run on supported OS" "$RED"
    printf "\n"
}
echo -e "\e[92m$(figlet -f small -w 80 'SPIDER  WEBX  STORE ')\e[0m"  # Changed font to 'small'
glitch_write "THIS IS THE OFFICIAL SCRIPT ✅. Unofficial clones are unsupported and may be unsafe. t.me/spide_3r OWNER ✅" "$BLUE"
export IP=$(curl -sS ipv4.icanhazip.com)
clear
if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
echo -e "${Green}  » Your OS Is Supported ( $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
echo -e "${Green}  » Your OS Is Supported ( $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
else
echo -e "${RED}[ERROR] Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
exit 1
fi
if [[ -z $IP ]]; then
echo -e "${RED}[ERROR] IP Address ( ${YELLOW}Not Detected${NC} )"
exit 1
else
echo -e "${Green}  » IP Address ( ${Green}$IP${NC} )"
fi
ALLOWED_IPS_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/Database"
if curl -s "$ALLOWED_IPS_URL" | grep -Ev '^###' | grep -q "$IP"; then
echo -e "${Green}  » Your IP is registered for installation."
else
echo -e "${ERROR}${GRAY} COULD NOT FIND ${NC} ${YELLOW}${IP}${NC} ${GRAY}IN THE DATABASE! INSTALLATION IS ABORTED.${NC}"
exit 1
fi
echo ""
read -p "$( echo -e "Press ${Green}[ ${NC}${Green}Enter${NC} ${Green}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear
REPO="https://raw.githubusercontent.com/spider660/Lau_Op/main/"
start=$(date +%s)
secs_to_human() {
echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
echo -e "${OK} ${BLUE} $1 ${FONT}"
}
function print_install() {
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
echo -e "${YELLOW} » $1 ${FONT} $OS_ID ($OS_CODENAME)"
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
sleep 1
}
function print_error() {
echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}
function print_success() {
if [[ 0 -eq $? ]]; then
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
echo -e "${Green} » $1 installed successfully"
echo -e "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"
sleep 2
fi
}
function is_root() {
if [[ 0 == "$UID" ]]; then
print_ok "Root user Start installation process"
else
print_error "The current user is not the root user, please switch to the root user and run the script again"
fi
}
print_install "Create xray directory"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown -R www-data:www-data /var/log/xray || true
chmod 755 /var/log/xray || true
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
export Kernel=$( uname -r )
export Arch=$( uname -m )
export IP=$( curl -s https://ipinfo.io/ip/ )
function first_setup() {
timedatectl set-timezone Africa/Nairobi
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
print_success "Directory Xray"

  OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"' | tr '[:upper:]' '[:lower:]')
  OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
  apt-get update -y || true

  if [[ "$OS_ID" == "ubuntu" || "${OS_LIKE:-}" == *"ubuntu"* ]]; then
    apt-get install -y --no-install-recommends software-properties-common lsb-release gnupg curl apt-transport-https || true
    # try to install haproxy via standard package, fallback to PPA/backports via safe installer
    if ! install_pkg_safely haproxy; then
      # try enabling universe/backports then retry
      enable_extra_repos
      install_pkg_safely haproxy || true
    fi
  elif [[ "$OS_ID" == "debian" || "${OS_LIKE:-}" == *"debian"* ]]; then
    apt-get install -y --no-install-recommends lsb-release gnupg curl apt-transport-https || true
    # add haproxy debian repo key and list (idempotent), then safe install
    curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || true
    echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net ${DIST_CODENAME}-backports main" | tee /etc/apt/sources.list.d/haproxy.list >/dev/null 2>&1 || true
    apt-get update -y || true
    install_pkg_safely haproxy || true
  else
    echo "Your OS is not supported ($OS_NAME)"
    exit 1
  fi
}
clear
function nginx_install() {
    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
    OS_CODENAME=$(grep -w VERSION_CODENAME /etc/os-release | cut -d= -f2)

    print_install "Installing latest Nginx from official repository for $OS_ID ($OS_CODENAME)"

    # Import nginx signing key (new keyring method)
    curl -fsSL https://nginx.org/keys/nginx_signing.key \
        | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

    if [[ "$OS_ID" == "ubuntu" ]]; then
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/ubuntu $OS_CODENAME nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    elif [[ "$OS_ID" == "debian" ]]; then
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/debian $OS_CODENAME nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    else
        echo "Your OS ($OS_ID) is not supported by this installer."
        return 1
    fi

    apt update -y
    apt install -y nginx
    print_success "Nginx installed successfully with full module support."
}

function haproxy_install() {
    print_install "Installing HAProxy (stable build)…"

    OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')

    # Remove any old HAProxy
    apt remove --purge -y haproxy* || true

    # === Recommended approach: use official distro packages ===
    # Ubuntu 22.04+ and Debian 12+ ship HAProxy 2.8+ directly.
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        apt update -y
        apt install -y haproxy
    else
        echo "Your OS ($OS_ID) is not supported by this installer."
        return 1
    fi

    systemctl enable haproxy
    systemctl start haproxy
    print_success "HAProxy installation complete!"
}
# Detect distro codename early for backports/universe (works on old and new releases)
DIST_CODENAME="$(lsb_release -cs 2>/dev/null || true)"
if [ -z "$DIST_CODENAME" ] && [ -f /etc/os-release ]; then
  DIST_CODENAME="$(awk -F= '/^VERSION_CODENAME=/{print $2}' /etc/os-release | tr -d '"' || true)"
fi
if [ -z "$DIST_CODENAME" ] && [ -f /etc/os-release ]; then
  DIST_CODENAME="$(awk -F= '/^VERSION_ID=/{print $2}' /etc/os-release | tr -d '"' | cut -d'.' -f1 || true)"
fi
export DIST_CODENAME

# idempotent: enable Ubuntu universe/multiverse or Debian backports
enable_extra_repos() {
  if ! command -v add-apt-repository >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends software-properties-common >/dev/null 2>&1 || true
  fi

  if grep -qi ubuntu /etc/os-release 2>/dev/null || [[ "${ID_LIKE:-}" == *"ubuntu"* ]]; then
    add-apt-repository -y universe >/dev/null 2>&1 || true
    add-apt-repository -y multiverse >/dev/null 2>&1 || true
    apt-get update -y >/dev/null 2>&1 || true
    return 0
  fi

  if grep -qi debian /etc/os-release 2>/dev/null || [[ "${ID_LIKE:-}" == *"debian"* ]]; then
    if [ -n "$DIST_CODENAME" ]; then
      BACKPORTS_FILE="/etc/apt/sources.list.d/${DIST_CODENAME}-backports.list"
      if [ ! -f "$BACKPORTS_FILE" ] || ! grep -q "backports" "$BACKPORTS_FILE" 2>/dev/null; then
        echo "deb http://deb.debian.org/debian ${DIST_CODENAME}-backports main" | tee "$BACKPORTS_FILE" >/dev/null 2>&1 || true
        apt-get update -y >/dev/null 2>&1 || true
      fi
    fi
    return 0
  fi
  return 0
}

# map some obsolete package names to modern alternatives
declare -A ALT_MAP=( \
  ["libcurl4-nss-dev"]="libcurl4-openssl-dev" \
  ["python"]="python3" \
  ["python2"]="python2" \
  ["python3-pip"]="python3-pip" \
)

# robust installer: apt candidate -> alternative -> enable repos -> backports -> repair
install_pkg_safely() {
  local pkg="$1" alt cand cand2

  # already present?
  if command -v "$pkg" >/dev/null 2>&1 || dpkg -s "$pkg" >/dev/null 2>&1; then
    return 0
  fi

  # 1) try apt candidate
  if apt-cache policy "$pkg" >/dev/null 2>&1; then
    cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')
    if [ -n "$cand" ] && [ "$cand" != "(none)" ]; then
      apt-get install -y --no-install-recommends "$pkg" && return 0 || true
    fi
  fi

  # 2) try mapped alternative
  alt="${ALT_MAP[$pkg]:-}"
  if [ -n "$alt" ]; then
    if apt-cache policy "$alt" >/dev/null 2>&1; then
      cand2=$(apt-cache policy "$alt" 2>/dev/null | awk '/Candidate:/ {print $2}')
      if [ -n "$cand2" ] && [ "$cand2" != "(none)" ]; then
        apt-get install -y --no-install-recommends "$alt" && return 0 || true
      fi
    fi
  fi

  # 3) enable extra repos and retry
  enable_extra_repos
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && return 0 || true
  if [ -n "$alt" ]; then
    apt-get install -y --no-install-recommends "$alt" >/dev/null 2>&1 && return 0 || true
  fi

  # 4) try distro backports
  if [ -n "$DIST_CODENAME" ]; then
    apt-get -t "${DIST_CODENAME}-backports" install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && return 0 || true
    if [ -n "$alt" ]; then
      apt-get -t "${DIST_CODENAME}-backports" install -y --no-install-recommends "$alt" >/dev/null 2>&1 && return 0 || true
    fi
  fi

  # 5) final repair attempt
  apt-get -f install -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && return 0 || true

  echo -e "${YELLOW}[WARN] Could not install '$pkg' or alternatives on ${OS_ID}-${DIST_CODENAME}. Continuing.${NC}"
  return 1
}

# --- NEW: helper to ensure a service unit is present by installing candidate packages ---
ensure_service_present() {
  local svc="$1"; shift
  local pkgs=( "$@" )
  local tried=0

  # If systemd already knows the unit, done
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${svc}.service"; then
    echo "[INFO] ${svc}.service already present."
    return 0
  fi

  echo "[INFO] Ensuring service '${svc}' (trying packages: ${pkgs[*]})"
  for p in "${pkgs[@]}"; do
    if install_pkg_safely "$p"; then
      tried=1
      systemctl daemon-reload >/dev/null 2>&1 || true
      if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${svc}.service"; then
        systemctl enable --now "${svc}.service" >/dev/null 2>&1 || true
        echo "[INFO] ${svc}.service installed and enabled (via package: $p)."
        return 0
      fi
      # try enabling common variants / best-effort
      safe_enable "${svc}" || true
      safe_restart "${svc}" || true
      if systemctl is-active --quiet "${svc}.service" 2>/dev/null || systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
        echo "[INFO] ${svc}.service active/enabled after install."
        return 0
      fi
    fi
  done

  # final attempt to reload and enable, then warn
  systemctl daemon-reload >/dev/null 2>&1 || true
  safe_enable "${svc}" || true
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${svc}.service"; then
    echo "[INFO] ${svc}.service present after retries."
    return 0
  fi

  echo -e "${YELLOW}[WARN] Could not ensure service '${svc}'. Some functionality may be missing.${NC}"
  return 1
}
# --- END: ensure_service_present ---

# Replace fragile base_package() content with resilient implementation
function base_package() {
  clear
  print_install "Installing the Required Packages"

  # core list; include key services so installer will try to install them across distros
  PKG_LIST=( \
    zip pwgen openssl netcat-openbsd socat cron bash-completion \
    figlet ca-certificates curl wget gnupg lsb-release jq net-tools dnsutils \
    iptables iptables-persistent netfilter-persistent make gcc g++ build-essential \
    pkg-config sed dirmngr python3 python3-pip python3-venv htop lsof tar unzip p7zip-full \
    git screen sudo rsyslog dos2unix bc xz-utils apt-transport-https \
    libnss3-dev libnspr4-dev libpam0g-dev libcap-ng-dev libcap-ng-utils \
    libselinux1-dev libevent-dev zlib1g-dev libssl-dev libsqlite3-dev \
    libxml-parser-perl cmake cmake-data speedtest-cli vnstat easy-rsa openvpn \
    msmtp-mta bsd-mailx rclone chrony ntpdate jq \
    nginx haproxy dropbear fail2ban # ensure these are attempted as packages
  )

  apt-get update -y || true
  failed_pkgs=()
  for p in "${PKG_LIST[@]}"; do
    [ -z "$p" ] && continue
    if ! install_pkg_safely "$p"; then
      failed_pkgs+=("$p")
    fi
  done

  apt-get clean -y || true
  apt-get autoremove -y || true

  if [ "${#failed_pkgs[@]}" -gt 0 ]; then
    echo -e "${YELLOW}[WARN] The following packages could not be installed: ${failed_pkgs[*]}${NC}"
    echo -e "${YELLOW}[WARN] Script will continue but some features may be unavailable.${NC}"
  fi

  print_success "Required Packages"

  # After attempting package installs, try to ensure service units exist & enabled
  ensure_service_present nginx nginx
  ensure_service_present haproxy haproxy
  ensure_service_present openvpn openvpn easy-rsa
  ensure_service_present dropbear dropbear
  ensure_service_present fail2ban fail2ban
  ensure_service_present netfilter-persistent netfilter-persistent iptables-persistent
}
clear
function install_domain() {
echo -e ""
clear
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
echo -e ""
read -p " Input Domain : " host1
echo -e ""
echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo $host1 > /etc/xray/domain
echo $host1 > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget "${REPO}ubuntu/cf.sh" && chmod +x cf.sh && ./cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}
clear
# Fix: restart_system - remove broken assignment and call datediff properly (safe)
restart_system(){
    MYIP=$(curl -sS ipv4.icanhazip.com || true)
    echo -e "\e[32mloading...\e[0m"
    clear
    izinsc="https://raw.githubusercontent.com/spider660/Lau_Op/main/keygen"
    rm -f /usr/bin/user
    username=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $2}' || echo "unknown")
    echo "$username" >/usr/bin/user 2>/dev/null || true
    expx=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $3}' || echo "")
    echo "$expx" >/usr/bin/e 2>/dev/null || true
    username=$(cat /usr/bin/user 2>/dev/null || echo "$username")
    oid=$(cat /usr/bin/ver 2>/dev/null || true)
    exp=$(cat /usr/bin/e 2>/dev/null || echo "$expx")
    clear
    # compute certificate days safely
    if [[ -n "$exp" ]]; then
        d1=$(date -d "$exp" +%s 2>/dev/null || echo 0)
        d2=$(date -d "$(date -d "0 days" +"%Y-%m-%d")" +%s 2>/dev/null || echo 0)
        certificate=$(( (d1 - d2) / 86400 ))
    else
        certificate=0
    fi

    DATE=$(date +'%Y-%m-%d')
    datediff() {
        if [ -z "$1" ] || [ -z "$2" ]; then
            echo -e " Expiry In   : N/A"
            return
        fi
        d1=$(date -d "$1" +%s 2>/dev/null || echo 0)
        d2=$(date -d "$2" +%s 2>/dev/null || echo 0)
        echo -e " Expiry In   : $(( (d1 - d2) / 86400 )) Days"
    }

    ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 || true)
    Info="(${green}Active${NC})"
    Error="(${RED}Expired${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(curl -s "$izinsc" | grep "$MYIP" | awk '{print $4}' || echo "")
    if [[ -n "$Exp1" && "$today" < "$Exp1" ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi

    # notify via telegram (best-effort)
    TIMES="10"
    CHATID="5459129686"
    KEY="6623979288:AAHeqh3tO_pZ3UVRz_bIN1qgyQuDPq0q0SI"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    TEXT=$(cat <<EOF
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
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
EOF
)
    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null 2>&1 || true
}
clear
function install_ssl() {
clear
print_install "Installing SSL On Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
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
function install_xray() {
clear
print_install "Core Xray Latest Version"
domainSock_dir="/run/xray"
sudo mkdir -p "$domainSock_dir"
sudo chown www-data:www-data "$domainSock_dir"
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"
sudo wget -O /etc/xray/config.json "${REPO}ubuntu/config.json" >/dev/null 2>&1
sudo wget -O /etc/systemd/system/runn.service "${REPO}ubuntu/runn.service" >/dev/null 2>&1
domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)
print_success "Core Xray Latest Version"
clear
sudo curl -s ipinfo.io/city | sudo tee /etc/xray/city
sudo curl -s ipinfo.io/org | cut -d " " -f 2-10 | sudo tee /etc/xray/isp
print_install "Installing Packet Configuration"
sudo wget -O /etc/haproxy/haproxy.cfg "${REPO}ubuntu/haproxy.cfg" >/dev/null 2>&1
sudo wget -O /etc/nginx/conf.d/xray.conf "${REPO}ubuntu/xray.conf" >/dev/null 2>&1
sudo sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sudo sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
sudo curl "${REPO}ubuntu/nginx.conf" > /etc/nginx/nginx.conf
# Replace previous cat command with a properly formatted command:
sudo bash -c 'printf "%s\n%s\n" "$(cat /etc/xray/xray.crt)" "$(cat /etc/xray/xray.key)" > /etc/haproxy/hap.pem'
sudo chmod +x /etc/systemd/system/runn.service
sudo rm -rf /etc/systemd/system/xray.service.d
sudo bash -c 'cat > /etc/systemd/system/xray.service <<EOF
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
EOF'
  # reload systemd and enable/start xray (best-effort)
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now xray >/dev/null 2>&1 || true
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
cd
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
cat > /etc/rc.local <<-END
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
END
chmod +x /etc/rc.local
echo -e "[INFO] Enabling and starting rc.local service..."
systemctl enable rc-local >/dev/null 2>&1
systemctl start rc-local.service >/dev/null 2>&1
echo -e "[INFO] Configuring rc.local to disable IPv6 on startup..."
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local >/dev/null 2>&1
echo -e "\n$(date)"
ln -fs /usr/share/zoneinfo/Africa/Nairobi /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "Password SSH"
}
function udp_mini(){
clear
print_install "Installing Service Limit IP & Quota"
wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel
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
clear
function ins_SSHD(){
clear
print_install "Installing SSHD"
wget -q -O /etc/ssh/sshd_config "${REPO}ubuntu/sshd" >/dev/null 2>&1
chmod 644 /etc/ssh/sshd_config || true
/etc/init.d/ssh restart >/dev/null 2>&1 || true
systemctl restart ssh >/dev/null 2>&1 || true
/etc/init.d/ssh status >/dev/null 2>&1 || true
print_success "SSHD"
}
clear
function ins_dropbear(){
clear
print_install "Installing Dropbear"
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
apt -y install vnstat > /dev/null 2>&1

    # Detect primary interface (best-effort)
    NET=""
    NET=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
    NET=${NET:-$(ip -o -4 addr show scope global | awk '{print $2; exit}')}
    NET=${NET:-eth0}

    /etc/init.d/vnstat restart > /dev/null 2>&1
    apt -y install libsqlite3-dev > /dev/null 2>&1

    # Build only if packaged source needed (safe - many distros already ship vnstat)
    if ! command -v vnstat > /dev/null 2>&1; then
        wget -q https://humdi.net/vnstat/vnstat-2.8.tar.gz -O /tmp/vnstat.tar.gz
        tar zxvf /tmp/vnstat.tar.gz -C /tmp > /dev/null 2>&1 || true
        if [ -d /tmp/vnstat-2.8 ]; then
            pushd /tmp/vnstat-2.8 > /dev/null 2>&1
            ./configure --prefix=/usr --sysconfdir=/etc > /dev/null 2>&1 || true
            make > /dev/null 2>&1 || true
            make install > /dev/null 2>&1 || true
            popd > /dev/null 2>&1
        fi
        rm -f /tmp/vnstat.tar.gz
        rm -rf /tmp/vnstat-2.8
    fi

    # Initialize vnstat database for chosen interface (guarded)
    if command -v vnstat > /dev/null 2>&1; then
        vnstat -u -i "$NET" > /dev/null 2>&1 || true
        sed -i "s/Interface \".*\"/Interface \"$NET\"/g" /etc/vnstat.conf > /dev/null 2>&1 || true
        chown vnstat:vnstat /var/lib/vnstat -R > /dev/null 2>&1 || true
        systemctl enable vnstat > /dev/null 2>&1 || true
        /etc/init.d/vnstat restart > /dev/null 2>&1 || true
    fi

    print_success "Vnstat"
}
function ins_openvpn(){
clear
print_install "Installing OpenVPN"
wget "${REPO}ubuntu/openvpn" &&  chmod +x openvpn && ./openvpn
/etc/init.d/openvpn restart
print_success "OpenVPN"
}
function ins_backup(){
clear
print_install "Installing Backup Server"
apt install rclone -y
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${REPO}ubuntu/rclone.conf"
}
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
clear
function ins_swab(){
clear
print_install "Installing Swap 1 G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget "${REPO}ubuntu/bbr.sh" &&  chmod +x bbr.sh && ./bbr.sh
print_success "Swap 1 G"
}
function ins_Fail2ban(){
clear
print_install "Installing Fail2ban"
apt -y install fail2ban > /dev/null 2>&1
sudo systemctl enable --now fail2ban
/etc/init.d/fail2ban restart
/etc/init.d/fail2ban status
if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
exit 0
else
mkdir /usr/local/ddos
fi
clear
echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear
wget -O /etc/kyt.txt "${REPO}ubuntu/issue.net"
print_success "Fail2ban"
}
function ins_epro() {
clear
print_install "Installing ePro WebSocket Proxy"
wget -O /usr/bin/ws "${REPO}ubuntu/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${REPO}ubuntu/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${REPO}ubuntu/ws.service" >/dev/null 2>&1
chmod +x /usr/bin/ws /etc/systemd/system/ws.service
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
for rule in "get_peers" "announce_peer" "find_node" "BitTorrent" "BitTorrent protocol" "peer_id=" ".torrent" "announce.php?passkey=" "torrent" "announce" "info_hash"; do
iptables -A FORWARD -m string --string "$rule" --algo bm -j DROP
done
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
print_success "ePro WebSocket Proxy installed successfully"
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
function menu(){
clear
print_install "Installing  Menu Packet"
wget "${REPO}ubuntu/menu.zip"
unzip menu.zip
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu
rm -rf menu.zip
}
function profile(){
clear
cat >/root/.profile <<EOF
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
cat >/etc/cron.d/daily_reboot <<'END'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Use online-capable wrapper to ensure scheduled reboot can notify and operate when online
0 5 * * * root /usr/local/sbin/daily_reboot
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
# write a network-aware /etc/rc.local that fetches remote iptables if online,
# restores rules and restarts netfilter-persistent if available.
cat >/etc/rc.local <<'EOF'
#!/bin/sh -e
# rc.local - executed at system boot (online-aware)

# Try to fetch a maintained iptables rules file from the repo if network is available
REPO_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/iptables.up.rules"
if command -v curl >/dev/null 2>&1; then
  curl -fsS --max-time 10 "$REPO_URL" -o /tmp/iptables.up.rules.new >/dev/null 2>&1 || true
  if [ -s /tmp/iptables.up.rules.new ]; then
    mv /tmp/iptables.up.rules.new /etc/iptables.up.rules || true
  else
    rm -f /tmp/iptables.up.rules.new >/dev/null 2>&1 || true
  fi
fi

# Restore iptables rules from local file if present
if command -v iptables-restore >/dev/null 2>&1 && [ -f /etc/iptables.up.rules ]; then
  iptables-restore < /etc/iptables.up.rules || true
fi

# Restart netfilter-persistent if unit exists
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files --type=service --all 2>/dev/null | grep -Fxq "netfilter-persistent.service"; then
  systemctl restart netfilter-persistent >/dev/null 2>&1 || true
fi

exit 0
EOF
chmod +x /etc/rc.local

  # Create online-capable daily reboot wrapper: waits briefly for network, notifies REPO, then reboots
  cat >/usr/local/sbin/daily_reboot <<'EOF'
  #!/usr/bin/env bash
  # online-capable daily_reboot: wait for network, notify repo, then reboot.

  LOGFILE="/var/log/daily_reboot.log"
  mkdir -p "$(dirname "$LOGFILE")"
  echo "$(date -Iseconds) daily_reboot started" >> "$LOGFILE"

  # Wait up to ~30s for simple network connectivity (curl to google)
  ONLINE=0
  if command -v curl >/dev/null 2>&1; then
    for i in 1 2 3 4 5; do
      if curl -s --head --max-time 6 https://www.google.com >/dev/null 2>&1; then
        ONLINE=1
        break
      fi
      sleep 3
    done
  fi

  # If online, attempt to notify remote repo endpoint (best-effort)
  if [ "$ONLINE" -eq 1 ] && command -v curl >/dev/null 2>&1; then
    REPO_PING="https://raw.githubusercontent.com/spider660/Lau_Op/main/ping.txt"
    curl -s --max-time 8 -o /dev/null "$REPO_PING" >/dev/null 2>&1 || true
    echo "$(date -Iseconds) notified remote endpoint" >> "$LOGFILE"
  fi

  # Perform graceful reboot
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --no-block reboot >/dev/null 2>&1 || true
  else
    /sbin/shutdown -r now >/dev/null 2>&1 || /sbin/reboot >/dev/null 2>&1 || true
  fi
EOF

  # ensure wrapper is executable and owned by root
  chmod 755 /usr/local/sbin/daily_reboot || true
  chown root:root /usr/local/sbin/daily_reboot || true

  # Reload systemd so new /etc/rc.local (and any unit files) are recognized
  systemctl daemon-reload >/dev/null 2>&1 || true

  # Enable & start rc-local (idempotent, non-fatal)
  systemctl enable --now rc-local.service >/dev/null 2>&1 || systemctl enable --now rc-local >/dev/null 2>&1 || true

  # Ensure cron is enabled and running, with service fallback for distros using 'service'
  if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^cron\.service'; then
    systemctl enable --now cron.service >/dev/null 2>&1 || true
    systemctl restart cron.service >/dev/null 2>&1 || true
  else
    service cron restart >/dev/null 2>&1 || true
    /etc/init.d/cron restart >/dev/null 2>&1 || true
  fi

  # ensure cron picked up new job files
  sleep 1
  systemctl is-active --quiet cron >/dev/null 2>&1 || service cron start >/dev/null 2>&1 || true

  print_success "Menu Packet"
}
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
function instal(){
clear
install_animation_start    # start existing install animation
matrix_start               # start matrix rain background
first_setup
nginx_install
base_package
make_folder_xray
install_domain
haproxy_install
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
install_animation_stop    # stop existing install animation
matrix_stop                # stop matrix background
}
hacker_banner
instal
spinner_stop >/dev/null 2>&1 || true

# --- Consolidated cleanup and finalization (single reboot prompt) ---
# show elapsed time
secs_to_human "$(($(date +%s) - ${start}))" 2>/dev/null || true

# clean temporary/install files
rm -rf /root/menu \
       /root/*.zip \
       /root/*.sh \
       /root/LICENSE \
       /root/README.md \
       /root/domain || true

# set hostname if username available
if [ -n "${username:-}" ]; then
    sudo hostnamectl set-hostname "$username" >/dev/null 2>&1 || true
fi

clear
echo -e "${green} Installation is completed. Happy Tunneling${NC}"
echo ""
glitch_write "Rebooting soon..." "$YELLOW"
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "

# ensure animations/spinners stopped, then reboot
install_animation_stop >/dev/null 2>&1 || true
matrix_stop >/dev/null 2>&1 || true
spinner_stop >/dev/null 2>&1 || true
reboot
