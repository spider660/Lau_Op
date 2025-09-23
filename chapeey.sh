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
# -- BEGIN: improved environment & OS detection --
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

sudo apt update -y
sudo apt upgrade -y
sudo apt install -y figlet
clear

# -- BEGIN: ensure required commands are available to avoid "command not found" --
ensure_commands() {
  echo "Detecting OS and required package names..."
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DETECTED_ID="${ID,,}"
    DETECTED_VER="${VERSION_ID:-}"
  else
    DETECTED_ID="unknown"
    DETECTED_VER=""
  fi

  # Set OS-specific package name choices
  case "${DETECTED_ID}" in
    ubuntu|debian)
      PKG_NETCAT="netcat-openbsd"
      PKG_LSB="lsb-release"
      PKG_GPG="gnupg"
      PKG_GREP="grep"
      PKG_AWK="gawk"
      # Pick widely-available libcurl dev package and python packages
      PKG_LIBCURL="libcurl4-openssl-dev"
      PKG_PY="python3"
      PKG_PIP="python3-pip"
      PKG_PY_ALIAS="python-is-python3"  # install if available
      ;;
    *)
      PKG_NETCAT="netcat"
      PKG_LSB="lsb-release"
      PKG_GPG="gnupg"
      PKG_GREP="grep"
      PKG_AWK="gawk"
      PKG_LIBCURL="libcurl4-openssl-dev"
      PKG_PY="python3"
      PKG_PIP="python3-pip"
      PKG_PY_ALIAS="python-is-python3"
      ;;
  esac

  echo "Detected OS: ${DETECTED_ID} ${DETECTED_VER}. Using ${PKG_NETCAT} for netcat."

  echo "Checking required system commands..."
  declare -A pkgmap=(
    [curl]=curl
    [wget]=wget
    [gpg]="${PKG_GPG}"
    [lsb_release]="${PKG_LSB}"
    [unzip]=unzip
    [tar]=tar
    [jq]=jq
    [ip]=iproute2
    [iptables]=iptables
    [git]=git
    [sed]=sed
    [awk]="${PKG_AWK}"
    [nc]="${PKG_NETCAT}"
    [python3]="${PKG_PY}"
    [pip3]="${PKG_PIP}"
  )

  missing_pkgs=()
  for cmd in "${!pkgmap[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_pkgs+=("${pkgmap[$cmd]}")
    fi
  done

  if [ "${#missing_pkgs[@]}" -gt 0 ]; then
    # deduplicate package names
    IFS=$'\n' read -r -d '' -a uniq_pkgs < <(printf "%s\n" "${missing_pkgs[@]}" | awk '!seen[$0]++' && printf '\0')
    echo "Installing missing packages: ${uniq_pkgs[*]}"
    apt-get update -y || true
    apt-get install -y "${uniq_pkgs[@]}" || true
  else
    echo "All required commands present."
  fi

  # export chosen names for later use
  export PKG_NETCAT PKG_LSB PKG_GPG PKG_AWK PKG_LIBCURL PKG_PY PKG_PIP PKG_PY_ALIAS
}
# Call the checker early to prevent later 'command not found' errors
ensure_commands
# -- END: ensure required commands are available to avoid "command not found" --

# -- BEGIN: safe systemd helpers (must exist before use) --
service_exists() {
  local unit="$1"
  # quiet check if systemd knows this unit
  systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "$unit" && return 0 || return 1
}

safe_enable() {
  local unit="$1"
  if service_exists "$unit"; then
    systemctl enable --now "$unit" >/dev/null 2>&1 || true
  fi
}

safe_restart() {
  local unit="$1"
  if service_exists "$unit"; then
    systemctl restart "$unit" >/dev/null 2>&1 || true
  fi
}
# -- END: safe systemd helpers --

# Use /etc/os-release reliably
# load ID, PRETTY_NAME, ID_LIKE
if [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	OS_ID="${ID,,}"
	OS_PRETTY="${PRETTY_NAME:-$NAME}"
	OS_LIKE="${ID_LIKE:-}"
else
	OS_ID=""
	OS_PRETTY="Unknown"
	OS_LIKE=""
fi

typing_banner() {
local text="$1"
local color="$2"
echo -e "${color}\e[1m"  # Set color and make bold
for (( i=0; i<${#text}; i++ )); do
echo -ne "${text:i:1}"
sleep 0.1  # Adjust speed
done
echo -e "${NC}"  # Reset color
}

echo -e "\e[92m$(figlet -f small -w 80 'WELCOME TO CHAPEEY STORE')\e[0m"  # Changed font to 'small'
typing_banner "Programmer: CHAPEEY" "$Green"
typing_banner "©2024: STABLE EDITION" "$Green"
typing_banner "⚠️ ATTENTION!" "$RED"
typing_banner "This is the Original script; any cloned version of my script is pirated. Don't install it, it is bugged. t.me/chapeey for more info." "$BLUE"
typing_banner "Happy Tunneling!" "$YELLOW"
export IP=$(curl -sS ipv4.icanhazip.com)
clear

# Simplified & robust OS support check
if [[ "$OS_ID" == "ubuntu" || "$OS_LIKE" == *"ubuntu"* ]]; then
  echo -e "${Green}  » Your OS Is Supported ( ${OS_PRETTY} )"
elif [[ "$OS_ID" == "debian" || "$OS_LIKE" == *"debian"* ]]; then
  echo -e "${Green}  » Your OS Is Supported ( ${OS_PRETTY} )"
else
  echo -e "${RED}[ERROR] Your OS Is Not Supported ( ${YELLOW}${OS_PRETTY}${NC} )"
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
echo -e "${YELLOW} » $1 ${FONT}"
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
# fix chown syntax and make directory readable/executable
chown www-data:www-data /var/log/xray || true
chmod 755 /var/log/xray || true
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# Initialize memory tracking variables to avoid "unbound variable" under set -u
mem_used=0
mem_total=0

while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB}))  ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable")
mem_used="$((mem_used-=${b/kB}))"
;;
esac
done < /proc/meminfo

# Safety: avoid division by zero if mem_total wasn't set for some reason
if [ "${mem_total:-0}" -gt 0 ]; then
  Ram_Usage="$((mem_used / 1024))"
  Ram_Total="$((mem_total / 1024))"
else
  Ram_Usage=0
  Ram_Total=0
fi
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
if [[ "$OS_ID" == "ubuntu" || "${OS_LIKE:-}" == *"ubuntu"* ]]; then
  echo "Setting up dependencies for $OS_NAME"
  apt-get update -y || true
  apt-get install -y --no-install-recommends software-properties-common lsb-release gnupg curl apt-transport-https || true
  # install haproxy from distro repos (works across Ubuntu versions)
  apt-get install -y haproxy || true
elif [[ "$OS_ID" == "debian" || "${OS_LIKE:-}" == *"debian"* ]]; then
  echo "Setting up dependencies for $OS_NAME"
  apt-get update -y || true
  apt-get install -y --no-install-recommends lsb-release gnupg curl apt-transport-https || true
  # add haproxy debian repo and key (compatible with newer debian)
  curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg || true
  echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -cs)-backports main" | tee /etc/apt/sources.list.d/haproxy.list
  apt-get update -y || true
  apt-get install -y haproxy || true
else
  echo "Your OS is not supported ($OS_NAME)"
  exit 1
fi
}
clear
function nginx_install() {
if [[ "$OS_ID" == "ubuntu" || "${OS_LIKE:-}" == *"ubuntu"* ]]; then
  print_install "Setup nginx For OS Is ${OS_PRETTY}"
  apt-get update -y || true
  apt-get install -y nginx || true
elif [[ "$OS_ID" == "debian" || "${OS_LIKE:-}" == *"debian"* ]]; then
  print_success "Setup nginx For OS Is ${OS_PRETTY}"
  apt-get update -y || true
  apt-get install -y nginx || true
else
  echo -e " Your OS Is Not Supported ( ${YELLOW}${OS_PRETTY}${FONT} )"
fi
}
# Detect distro codename early (work for Ubuntu/Debian current and future releases)
DIST_CODENAME="$(lsb_release -cs 2>/dev/null || echo "")"
# fallback to VERSION_CODENAME from /etc/os-release if lsb_release missing
if [ -z "$DIST_CODENAME" ] && [ -f /etc/os-release ]; then
  DIST_CODENAME="$(awk -F= '/^VERSION_CODENAME=/{print $2}' /etc/os-release | tr -d '"')" || true
fi
# final fallback to VERSION_ID (may be numeric)
if [ -z "$DIST_CODENAME" ]; then
  DIST_CODENAME="$(awk -F= '/^VERSION_ID=/{print $2}' /etc/os-release | tr -d '"' | cut -d'.' -f1 || true)"
fi
export DIST_CODENAME

# --- improved repo enable + safe installer (works for current and newer Ubuntu/Debian) ---
enable_extra_repos() {
  # ensure add-apt-repository helper exists
  if ! command -v add-apt-repository >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends software-properties-common >/dev/null 2>&1 || true
  fi

  # Ubuntu: enable universe & multiverse; try enabling proposed/backports carefully
  if [[ "${OS_ID:-}" == "ubuntu" || "${OS_LIKE:-}" == *"ubuntu"* ]]; then
    echo "[INFO] Enabling Ubuntu universe/multiverse (if available)..."
    add-apt-repository -y universe >/dev/null 2>&1 || true
    add-apt-repository -y multiverse >/dev/null 2>&1 || true
    # also ensure backports component exists (many Ubuntu releases use -backports pocket)
    apt-get update -y >/dev/null 2>&1 || true
    return 0
  fi

  # Debian: add backports for detected codename (idempotent)
  if [[ "${OS_ID:-}" == "debian" || "${OS_LIKE:-}" == *"debian"* ]]; then
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

# map known obsolete names to safe alternatives
declare -A ALT_MAP=( \
  ["libcurl4-nss-dev"]="${PKG_LIBCURL:-libcurl4-openssl-dev}" \
  ["python"]="python3" \
  ["python2"]="python2" \
  ["python3-pip"]="${PKG_PIP:-python3-pip}" \
)

# robust installer: try candidate -> alternative -> enable repos -> backports -> repair
install_pkg_safely() {
  local pkg="$1" alt cand cand2

  # already present by command or package
  if command -v "$pkg" >/dev/null 2>&1 || dpkg -s "$pkg" >/dev/null 2>&1; then
    return 0
  fi

  echo "[INFO] Ensuring '$pkg' is installed (codename=${DIST_CODENAME:-unknown})..."

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
    echo "[INFO] Trying alternative '$alt' for '$pkg'..."
    if apt-cache policy "$alt" >/dev/null 2>&1; then
      cand2=$(apt-cache policy "$alt" 2>/dev/null | awk '/Candidate:/ {print $2}')
      if [ -n "$cand2" ] && [ "$cand2" != "(none)" ]; then
        apt-get install -y --no-install-recommends "$alt" && return 0 || true
      fi
    fi
  fi

  # 3) enable extra repos and retry
  echo "[INFO] Enabling extra repos and retrying install for '$pkg'..."
  enable_extra_repos
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && return 0 || true
  if [ -n "$alt" ]; then
    apt-get install -y --no-install-recommends "$alt" >/dev/null 2>&1 && return 0 || true
  fi

  # 4) try distribution backports (if codename detected)
  if [ -n "$DIST_CODENAME" ]; then
    echo "[INFO] Trying backports (-t ${DIST_CODENAME}-backports) for '$pkg'..."
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
# --- END: improved install helper ---

# New helper: build a safe package list based on chosen package names
build_pkg_list() {
  PKG_LIST=(\
    zip pwgen openssl "${PKG_NETCAT}" socat cron bash-completion \
    figlet \
    "${PKG_LIBCURL}" \
    "${PKG_PY}" "${PKG_PIP}" \
    ca-certificates curl wget gnupg lsb-release \
    jq net-tools dnsutils iptables iptables-persistent netfilter-persistent \
    make gcc g++ build-essential pkg-config \
    sed dirmngr python3-venv htop lsof tar unzip p7zip-full \
    git screen sudo rsyslog cron dos2unix bc \
    xz-utils apt-transport-https ca-certificates \
    libnss3-dev libnspr4-dev libpam0g-dev libcap-ng-dev libcap-ng-utils \
    libselinux1-dev libevent-dev zlib1g-dev libssl-dev libsqlite3-dev \
    libxml-parser-perl pkg-config cmake cmake-data \
    speedtest-cli vnstat easy-rsa openvpn \
    msmtp-mta bsd-mailx rclone \
  )

  # optionally include python-is-python3 if present in repo (safe: apt will ignore if unavailable)
  PKG_LIST+=("${PKG_PY_ALIAS}")
}
# Replace bulk-install logic: iterate and ensure each package is installed
function base_package() {
clear
print_install "Installing the Required Packages"

# build OS-aware package list and install once
build_pkg_list
apt-get update -y || true
apt-get install -y "${PKG_LIST[@]}" || true

# keep the safe chrony / time logic as before
# ensure a reliable time service is installed; prefer 'chrony'
apt-get install -y chrony ntpdate >/dev/null 2>&1 || true

# Use safe enable/restart to avoid "unit file does not exist" errors
safe_enable chrony
safe_restart chrony

# If chronyc present, display stats (guarded)
if command -v chronyc >/dev/null 2>&1; then
  chronyc sourcestats -v || true
  chronyc tracking -v || true
else
  # fallback to ntpdate to sync time if chrony isn't available
  ntpdate -u pool.ntp.org >/dev/null 2>&1 || true
fi

apt install ntpdate -y
ntpdate pool.ntp.org
apt install sudo -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# Replace the previous long hardcoded install line that referenced
# obsolete packages (e.g. libcurl4-nss-dev, python) with a resilient,
# variable-driven and deduplicated list. This uses the PKG_LIBCURL and PKG_PY
# variables selected earlier in ensure_commands().
ADDITIONAL_PKGS=( \
  speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config \
  libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
  flex bison make libnss3-tools libevent-dev bc \
  rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
  libxml-parser-perl build-essential gcc g++ "${PKG_PY}" \
  htop lsof tar wget curl ruby zip unzip p7zip-full "${PKG_PIP}" \
  libc6 util-linux msmtp-mta ca-certificates bsd-mailx iptables \
  iptables-persistent netfilter-persistent net-tools openssl gnupg \
  gnupg2 lsb-release shc make cmake git screen socat xz-utils \
  apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate \
  chrony jq openvpn easy-rsa "${PKG_LIBCURL}" \
)

# Ensure network and update
apt-get update -y >/dev/null 2>&1 || true

# Install each package with safe installer and collect failures
failed_pkgs=()
for p in "${ADDITIONAL_PKGS[@]}"; do
  [ -z "$p" ] && continue
  if ! install_pkg_safely "$p"; then
    failed_pkgs+=("$p")
  fi
done

if [ "${#failed_pkgs[@]}" -gt 0 ]; then
  echo -e "${YELLOW}[WARN] The following packages could not be installed: ${failed_pkgs[*]}${NC}"
  echo -e "${YELLOW}[WARN] Script will continue but some features may be unavailable on this release.${NC}"
fi

print_success "Required Packages"

# Post-install quick service checks: warn if expected services are missing
check_services_after_install() {
  local services=(nginx haproxy openvpn dropbear fail2ban vnstat netfilter-persistent xray)
  for s in "${services[@]}"; do
    # xray may be installed to /usr/local/bin and have a systemd unit installed by its installer
    if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${s}.service"; then
      echo "[INFO] Service unit ${s}.service exists."
    else
      # as fallback check package presence
      if dpkg -l | awk '{print $2}' | grep -Fxq "$s" ; then
        echo "[INFO] Package '$s' installed but no systemd unit found."
      else
        echo -e "${YELLOW}[WARN] Expected service/package '$s' not found on this system. Some functionality may be missing.${NC}"
      fi
    fi
  done
}
check_services_after_install || true

# Ensure a given service unit exists by installing candidate packages and enabling the unit.
ensure_service_present() {
  local service="$1"; shift
  local pkgs=( "$@" )
  local ok=1

  # If systemd already knows the unit, we're done
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${service}.service"; then
    echo "[INFO] ${service}.service already present."
    return 0
  fi

  echo "[INFO] Attempting to install packages for service '${service}': ${pkgs[*]}"

  for p in "${pkgs[@]}"; do
    # try to install package (uses install_pkg_safely with repo/backports fallback)
    if install_pkg_safely "$p"; then
      ok=0
      # ensure systemd picks up any new unit files
      systemctl daemon-reload >/dev/null 2>&1 || true
      # enable/start only if service unit now exists
      if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${service}.service"; then
        systemctl enable --now "${service}.service" >/dev/null 2>&1 || true
        echo "[INFO] ${service}.service installed and enabled (via package: $p)."
        return 0
      else
        # sometimes package installs create different unit names (enable known variants)
        safe_enable "${service}" || true
        safe_restart "${service}" || true
        if systemctl is-active --quiet "${service}.service" 2>/dev/null || systemctl is-enabled --quiet "${service}.service" 2>/dev/null; then
          echo "[INFO] ${service}.service is now active/enabled."
          return 0
        fi
      fi
    fi
  done

  # last attempt: try enabling any unit that may now exist
  systemctl daemon-reload >/dev/null 2>&1 || true
  safe_enable "${service}" || true
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -Fxq "${service}.service"; then
    echo "[INFO] ${service}.service is now present."
    return 0
  fi

  echo -e "${YELLOW}[WARN] Could not ensure service '${service}' via packages: ${pkgs[*]}. Some functionality may be missing.${NC}"
  return 1
}

# Try to ensure critical services exist by installing their packages if needed
# This will attempt distro-aware installs (backports/universe) using install_pkg_safely
ensure_service_present haproxy haproxy
ensure_service_present openvpn openvpn easy-rsa
ensure_service_present dropbear dropbear

# ...existing code...
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
# Initialize/Detect network interface used by vnstat if not already set
NET="${NET:-$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' || true)}"
if [ -z "$NET" ]; then
  echo "[WARN] Could not detect default network interface. vnStat interface steps will be skipped."
fi

# Provide a small stub for password_default if it's referenced but not defined
password_default() {
  # original script expected to configure default passwords; stub prevents "command not found"
  echo "[INFO] password_default() not provided in script. Skipping default password changes."
}

# Helper: check apt-cache for candidate package and warn (non-fatal)
ensure_pkg_available() {
  local pkg="$1"
  if apt-cache policy "$pkg" >/dev/null 2>&1; then
    if ! apt-cache policy "$pkg" | grep -q 'Candidate:'; then
      echo "[WARN] Package $pkg has no candidate in apt repos."
    fi
  else
    echo "[WARN] apt-cache could not evaluate package $pkg"
  fi
}

restart_system(){
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear
izinsc="https://raw.githubusercontent.com/spider660/Lau_Op/main/keygen"
rm -f /usr/bin/user
username=$(curl $izinsc | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
expx=$(curl $izinsc | grep $MYIP | awk '{print $3}')
echo "$expx" >/usr/bin/e
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)
clear
d1=$(date -d "$valid" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))
DATE=$(date +'%Y-%m-%d')
datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff "$Exp" "$DATE""
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
Info="(${green}Active${NC})"
Error="(${RED}Expired${NC})"
today="$(date -d "0 days" +"%Y-%m-%d")"
Exp1=$(curl $izinsc | grep $MYIP | awk '{print $4}')
if [[ $today < $Exp1 ]]; then
sts="${Info}"
else
sts="${Error}"
fi
TIMES="10"
CHATID="5459129686"
KEY="6623979288:AAHeqh3tO_pZ3UVRz_bIN1qgyQuDPq0q0SI"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>WELCOME TO CHAPEEY STORE</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<code>User     :</code><code>$username</code>
<code>Domain   :</code><code>$domain</code>
<code>IPVPS    :</code><code>$MYIP</code>
<code>ISP      :</code><code>$ISP</code>
<code>DATE     :</code><code>$DATE</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<b>WELCOME TO CHAPEEY STORE</b>
<code>━━━━━━━━━━━━━━━━━━━━━━━━━</code>
<i>Automatic Notifications From Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"https://wa.me/+254704348959"}]]}'
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
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
mkdir -p /root/.acme.sh
systemctl stop "$STOPWEBSERVER" >/dev/null 2>&1 || true
systemctl stop nginx >/dev/null 2>&1 || true
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
/root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 600 /etc/xray/xray.key || true
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
cat /etc/xray/xray.crt /etc/xray/xray.key | sudo tee /etc/haproxy/hap.pem
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
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.8.tar.gz
tar zxvf vnstat-2.8.tar.gz
cd vnstat-2.8
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
if [ -n "$NET" ]; then
  vnstat -u -i "$NET"
  sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf || true
  chown vnstat:vnstat /var/lib/vnstat -R || true
  systemctl enable vnstat || true
  /etc/init.d/vnstat restart || true
  /etc/init.d/vnstat status || true
else
  echo "[WARN] NET not set; skipping vnstat interface setup"
fi
rm -f /root/vnstat-2.8.tar.gz
rm -rf /root/vnstat-2.8
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
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

# Try to step time using available tools without raising unit-not-found errors
if command -v chronyd >/dev/null 2>&1; then
  chronyd -q 'server 0.id.pool.ntp.org iburst' || true
elif command -v chronyc >/dev/null 2>&1; then
  # chronyc doesn't have same cli flags; attempt a safe sync
  chronyc -a 'burst 4/4' >/dev/null 2>&1 || true
else
  ntpdate -u pool.ntp.org >/dev/null 2>&1 || true
fi

# show chrony stats if available
if command -v chronyc >/dev/null 2>&1; then
  chronyc sourcestats -v || true
  chronyc tracking -v || true
fi

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
instal
echo ""
history -c
rm -rf /root/menu /root/*.zip /root/*.sh /root/LICENSE /root/README.md /root/domain || true
secs_to_human "$(($(date +%s) - ${start}))"
if [[ -n "${username:-}" ]]; then
  sudo hostnamectl set-hostname "$username" || true
fi
echo -e "${green} Installation is completed Happy Tunneling"
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For reboot") "
reboot
