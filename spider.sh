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

# Ensure script is run as root before running apt/sudo commands at top
if [ "$(id -u)" -ne 0 ]; then
	>&2 echo "This installer must be run as root. Exiting."
	exit 1
fi

sudo apt update -y
sudo apt upgrade -y
sudo apt install -y figlet
clear
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
echo -e "\e[92m$(figlet -f small -w 80 'WELCOME TO SPIDER STORE')\e[0m"  # Changed font to 'small'
typing_banner "Programmer: SPIDER" "$Green"
typing_banner "©2024: STABLE EDITION" "$Green"
typing_banner "⚠️ ATTENTION!" "$RED"
typing_banner "This is the Original script; any cloned version of my script is pirated. Don't install it, it is bugged. t.me/spid_3r for more info." "$BLUE"
typing_banner "Happy Tunneling!" "$YELLOW"
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

# OLD: remove remote allowlist check
# ALLOWED_IPS_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/Database"
# if curl -s "$ALLOWED_IPS_URL" | grep -Ev '^###' | grep -q "$IP"; then
# echo -e "${Green}  » Your IP is registered for installation."
# else
# echo -e "${ERROR}${GRAY} COULD NOT FIND ${NC} ${YELLOW}${IP}${NC} ${GRAY}IN THE DATABASE! INSTALLATION IS ABORTED.${NC}"
# exit 1
# fi

# NEW: require fixed password "123456" first, then prompt for any admin name
read -s -p "$(echo -e ${Green}Enter admin password:${NC} )" ADMIN_PASS
echo
if [ "${ADMIN_PASS}" != "wantam" ]; then
    echo -e "${RED}Incorrect password. Installation aborted.${NC}"
    exit 1
fi

read -p "$(echo -e ${Green}Enter Your name:${NC} )" ADMIN_NAME
if [ -z "${ADMIN_NAME}" ]; then
    ADMIN_NAME="admin"
fi
export ADMIN_NAME

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

# Replace the older per-OS install blocks with a robust universal installer
ensure_dependencies() {
	# non-interactive
	export DEBIAN_FRONTEND=noninteractive
	set -o errexit
	set -o nounset
	set -o pipefail

	# Detect OS fields robustly
	OS_ID="$(. /etc/os-release && echo "${ID:-}" )"
	OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-}" | tr -d '"')"
	OS_VER="$(. /etc/os-release && echo "${VERSION_ID:-}" )"
	OS_CODENAME="$(lsb_release -cs 2>/dev/null || echo "")"

	echo -e "${Green}  » Detected OS: ${OS_NAME} (ID=${OS_ID} VERSION=${OS_VER} CODENAME=${OS_CODENAME})${FONT}"

	# helper: wait for apt/dpkg locks
	apt_wait_lock() {
		local n=0
		while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
			n=$((n+1))
			if [ "$n" -gt 30 ]; then
				echo -e "${ERROR} apt/dpkg lock held too long. Aborting."
				return 1
			fi
			echo -e "${YELLOW} Waiting for apt/dpkg lock... (${n})${FONT}"
			sleep 2
		done
		return 0
	}

	# helper: retry wrapper
	retry_cmd() {
		local tries=4
		local wait=3
		local i=0
		until "$@"; do
			i=$((i+1))
			if [ "$i" -ge "$tries" ]; then
				echo -e "${ERROR} Command failed after ${tries} attempts: $*"
				return 1
			fi
			echo -e "${YELLOW}Retrying: $* (${i}/${tries})${FONT}"
			sleep "$wait"
		done
		return 0
	}

	# update apt lists safely
	apt_wait_lock
	retry_cmd apt-get update -y
	retry_cmd apt-get upgrade -y || true

	# Add common backports or safe repos for older distros (best-effort)
	if [ "$OS_ID" = "debian" ]; then
		# try to enable backports for common codenames if not present
		if [ -n "$OS_CODENAME" ] && ! grep -q "backports" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
			echo "deb http://deb.debian.org/debian ${OS_CODENAME}-backports main" >/etc/apt/sources.list.d/${OS_CODENAME}-backports.list || true
			retry_cmd apt-get update -y || true
		fi
	fi

	# Install a comprehensive package set needed by the rest of the script
	COMMON_PKGS=(
		apt-transport-https ca-certificates curl wget gnupg lsb-release software-properties-common
		build-essential unzip zip sudo dnsutils lsof htop net-tools iproute2 iptables iptables-persistent
		netfilter-persistent cron chrony ntpdate rsyslog bash-completion jq git sed gawk coreutils openssl
		ruby figlet pwgen make gcc g++ python3-pip p7zip-full netcat socat gnupg2 gpg rsync bc
	)

	apt_wait_lock
	retry_cmd apt-get install -y --no-install-recommends "${COMMON_PKGS[@]}"

	# optional extras
	retry_cmd apt-get install -y wondershaper || true
	# install lolcat if ruby gem present
	if command -v gem >/dev/null 2>&1; then
		gem install lolcat || true
	fi

	# HAProxy repo handling
	if [ "$OS_ID" = "debian" ]; then
		echo -e "${Green}  » Configuring HAProxy repo for Debian${FONT}"
		apt_wait_lock
		retry_cmd curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg || true
		CODENAME="${OS_CODENAME:-$(lsb_release -cs 2>/dev/null || echo stable)}"
		echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net ${CODENAME}-backports main" >/etc/apt/sources.list.d/haproxy.list || true
		apt_wait_lock
		retry_cmd apt-get update -y || true
		retry_cmd apt-get install -y haproxy || true
	elif [ "$OS_ID" = "ubuntu" ]; then
		echo -e "${Green}  » Ensuring HAProxy on Ubuntu (PPA fallback)${FONT}"
		# add-apt-repository sometimes missing; install it first
		apt_wait_lock
		retry_cmd apt-get install -y software-properties-common || true
		if command -v add-apt-repository >/dev/null 2>&1; then
			retry_cmd add-apt-repository -y ppa:vbernat/haproxy || true
			apt_wait_lock
			retry_cmd apt-get update -y || true
		fi
		retry_cmd apt-get install -y haproxy || true
	else
		echo -e "${YELLOW}  » Unknown distro; attempting to install haproxy, nginx, openvpn if available${FONT}"
		retry_cmd apt-get install -y haproxy || true
	fi

	# Ensure nginx, openvpn, netfilter are installed
	apt_wait_lock
	retry_cmd apt-get install -y --no-install-recommends nginx openvpn netfilter-persistent iptables-persistent || true

	# Enable and restart time sync services (safe)
	systemctl enable chrony >/dev/null 2>&1 || true
	systemctl restart chrony >/dev/null 2>&1 || true

	# Cleanup
	apt-get -y autoremove || true
	apt-get -y clean || true

	echo -e "${Green}  » Dependencies installed (best-effort) for ${OS_NAME}.${FONT}"
}

# ---------------- NEW: spinner, logging, and directory fix helpers ----------------
LOGFILE="/var/log/spider-install.log"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
exec 3>>"$LOGFILE"

spinner_start() {
	local msg="${1:-Working...}"
	printf "%s " "$msg"
	# background pid stored in SPINNER_PID
	(
		i=0
		chars='/-\|'
		while :; do
			printf "\b${chars:i++%${#chars}:1}"
			sleep 0.12
		done
	) &
	SPINNER_PID=$!
	# ensure spinner is killed on exit of caller
}

spinner_stop() {
	if [ -n "${SPINNER_PID:-}" ]; then
		kill "$SPINNER_PID" >/dev/null 2>&1 || true
		wait "$SPINNER_PID" 2>/dev/null || true
		unset SPINNER_PID
		printf "\b" 2>/dev/null || true
		echo " done."
	fi
}

log() {
	local lvl="$1"; shift
	echo "[$(date +'%Y-%m-%d %H:%M:%S')] ${lvl} $*" >&3
}

# Ensure directories used by the script exist and have sane perms
ensure_dirs_and_permissions() {
	log INFO "Ensuring required directories and permissions"
	local dirs=(
		/etc/xray /var/log/xray /var/www/html /usr/local/sbin /usr/bin /etc/haproxy /etc/nginx/conf.d
		/etc/systemd/system /root/.acme.sh /etc/ssh /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
		/var/lib/kyt /etc/kyt /etc/user-create /usr/local/kyt
	)
	for d in "${dirs[@]}"; do
		if [ ! -d "$d" ]; then
			mkdir -p "$d" 2>/dev/null || { log ERROR "Failed to create $d"; }
			log INFO "Created $d"
		fi
	done

	# Files
	touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log || true
	# Best-effort ownership/perms
	chown -R www-data:www-data /var/log/xray 2>/dev/null || true
	chmod -R 755 /usr/local/sbin /usr/bin /var/www/html 2>/dev/null || true

	# Ensure systemd directories exist
	mkdir -p /etc/systemd/system || true

	log INFO "Directory and permission setup complete"
}

# Call the new function (replaces earlier simple per-OS blocks)
ensure_dependencies
ensure_dirs_and_permissions
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
print_ok "Root user detected, starting installation process"
else
print_error "The current user is not root. Switch to root and run the script again."
exit 1
fi
}
print_install "Create xray directory"

# Create necessary directories and files
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# Calculate RAM usage
mem_used=0
mem_total=0
while IFS=":" read -r a b; do
case $a in
"MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
"Shmem") ((mem_used+=${b/kB})) ;;
"MemFree" | "Buffers" | "Cached" | "SReclaimable") ((mem_used-=${b/kB})) ;;
esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"

# Export system info
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# First setup function
function first_setup() {
timedatectl set-timezone Africa/Nairobi

# Preconfigure iptables-persistent to auto-save
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

print_success "Directory Xray"

OS_ID=$(grep -w ID /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')
OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d '=' -f 2 | tr -d '"')

if [[ "$OS_ID" == "ubuntu" ]]; then
echo "Setting up dependencies for $OS_NAME"
apt update -y
apt-get install --no-install-recommends software-properties-common -y

# HAProxy check
if ! dpkg -l | grep -qw haproxy; then
echo "Installing HAProxy..."
apt install haproxy -y
else
echo "HAProxy is already installed."
fi
elif [[ "$OS_ID" == "debian" ]]; then
echo "Setting up dependencies for $OS_NAME"
apt update -y
apt-get install --no-install-recommends software-properties-common -y

if ! dpkg -l | grep -qw haproxy; then
echo "Installing HAProxy..."
apt install haproxy -y
else
echo "HAProxy is already installed."
fi
fi
}
clear
LATEST_PPA=$(apt-cache madison haproxy | awk '{print $3}' | grep -o 'ppa:[^ ]*' | sort -u | tail -n1)
if [[ "$OS_ID" == "ubuntu" ]]; then
if [[ -z "$LATEST_PPA" ]]; then
echo "No PPA found for HAProxy. Adding the default PPA for HAProxy..."
add-apt-repository ppa:vbernat/haproxy -y
else
echo "Adding the latest PPA for HAProxy: $LATEST_PPA"
add-apt-repository "$LATEST_PPA" -y
fi
apt update -y
apt-get install haproxy -y
elif [[ "$OS_ID" == "debian" ]]; then
echo "Setting up dependencies for $OS_NAME"
curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -cs)-backports main" | tee /etc/apt/sources.list.d/haproxy.list
apt-get update -y
apt-get install haproxy -y
else
echo "Your OS is not supported ($OS_NAME)"
exit 1
fi
}

clear

function nginx_install() {
if [[ "$OS_ID" == "ubuntu" ]]; then
print_install "Setup nginx For OS: $OS_NAME"
apt-get install nginx -y
elif [[ "$OS_ID" == "debian" ]]; then
print_install "Setup nginx For OS: $OS_NAME"
apt-get install nginx -y
else
echo -e "Your OS is not supported (${YELLOW}$OS_NAME${FONT})"
fi
}

function base_package() {
clear
print_install "Installing the Required Packages"

apt install -y zip pwgen openssl netcat socat cron bash-completion figlet
apt update -y
apt upgrade -y
apt dist-upgrade -y

systemctl enable chronyd
systemctl restart chronyd
systemctl enable chrony
systemctl restart chrony
chronyc sourcestats -v
chronyc tracking -v

apt install -y ntpdate sudo debconf-utils
ntpdate pool.ntp.org

apt-get clean all
apt-get autoremove -y
apt-get remove --purge exim4 ufw firewalld -y

apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make \
libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl \
ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta \
ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools \
openssl ca-certificates gnupg gnupg2 lsb-release shc cmake git screen socat xz-utils \
apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa

print_success "Required Packages Installed"
}

clear
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
echo -e " \e[1;32mPlease Enter Your Domain $NC"
echo -e " ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -p " Input Domain : " host1
echo "IP=" >> /var/lib/kyt/ipvps.conf
echo "$host1" > /etc/xray/domain
echo "$host1" > /root/domain
echo ""
elif [[ $host == "2" ]]; then
wget "${REPO}ubuntu/cf.sh" -O /root/cf.sh
chmod +x /root/cf.sh
/root/cf.sh
rm -f /root/cf.sh
clear
else
print_install "Random Subdomain/Domain is Used"
clear
fi
}

clear

restart_system() {
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

IZINSC_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/keygen"
rm -f /usr/bin/user /usr/bin/e

username=$(curl -s "$IZINSC_URL" | grep "$MYIP" | awk '{print $2}')
echo "$username" > /usr/bin/user

expx=$(curl -s "$IZINSC_URL" | grep "$MYIP" | awk '{print $3}')
echo "$expx" > /usr/bin/e

username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver 2>/dev/null || echo "N/A")
exp=$(cat /usr/bin/e)
domain=$(cat /root/domain)

DATE=$(date +'%Y-%m-%d')

datediff() {
d1=$(date -d "$1" +%s)
d2=$(date -d "$2" +%s)
echo -e "$COLOR1 $NC Expiry In : $(( (d1 - d2) / 86400 )) Days"
}
mai="datediff \"$exp\" \"$DATE\""
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
Info="(${green}Active${NC})"
Error="(${RED}Expired${NC})"
today=$(date -d "0 days" +"%Y-%m-%d")
Exp1=$(curl -s "$IZINSC_URL" | grep "$MYIP" | awk '{print $4}')

if [[ "$today" < "$Exp1" ]]; then
sts="${Info}"
else
sts="${Error}"
fi

TIMES="10"
CHATID="5459129686"
KEY="6623979288:AAHeqh3tO_pZ3UVRz_bIN1qgyQuDPq0q0SI"
URL="https://api.telegram.org/bot$KEY/sendMessage"
TIMEZONE=$(printf '%(%H:%M:%S)T')
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
<i>Automatic Notifications From Github</i>
'&reply_markup={\"inline_keyboard\":[[{\"text\":\"ᴏʀᴅᴇʀ\",\"url\":\"https://wa.me/+254112011036\"}],\
[{\"text\":\"ᴜᴘᴅᴀᴛᴇs\",\"url\":\"https://t.me/spid_3r\"}],\
[{\"text\":\"sᴜᴘᴘᴏʀᴛ\",\"url\":\"https://t.me/spid_3r\"}]]}&parse_mode=html'

curl -s --max-time "$TIMES" -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" "$URL" >/dev/null
}

clear

function install_ssl() {
clear
print_install "Installing SSL On Domain"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt

# ensure domain exists
domain="$(cat /root/domain 2>/dev/null || true)"
if [ -z "$domain" ]; then
  echo -e "${RED}No domain configured in /root/domain — cannot issue certificate.${NC}"
  return 1
fi

# Stop common webserver services that may bind :80 (safe, best-effort)
for svc in nginx apache2 httpd; do
  if systemctl list-units --type=service --all | grep -q "^${svc}.service"; then
    systemctl stop "$svc" >/dev/null 2>&1 || true
  fi
done

rm -rf /root/.acme.sh
mkdir -p /root/.acme.sh

curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh || { echo "Failed to download acme.sh"; return 1; }
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
# Issue cert (standalone will bind :80 temporarily)
if ! /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 >/dev/null 2>&1; then
  echo -e "${RED}acme.sh failed to issue certificate for ${domain}${NC}"
  return 1
fi

# Install the cert
/root/.acme.sh/acme.sh --installcert -d "$domain" \
  --fullchainpath /etc/xray/xray.crt \
  --keypath /etc/xray/xray.key --ecc >/dev/null 2>&1 || { echo "Installing certificate failed"; return 1; }

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

mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
mkdir -p /usr/bin/xray /var/log/xray /var/www/html
mkdir -p /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip
mkdir -p /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh
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

echo "& plughin Account" >> /etc/vmess/.vmess.db
echo "& plughin Account" >> /etc/vless/.vless.db
echo "& plughin Account" >> /etc/trojan/.trojan.db
echo "& plughin Account" >> /etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >> /etc/ssh/.ssh.db
echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

function install_xray() {
clear
print_install "Core Xray Latest Version"

domainSock_dir="/run/xray"
mkdir -p "$domainSock_dir"
chown www-data:www-data "$domainSock_dir"

latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases \
| grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)

bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"

wget -q -O /etc/xray/config.json "${REPO}ubuntu/config.json"
wget -q -O /etc/systemd/system/runn.service "${REPO}ubuntu/runn.service"

domain=$(cat /etc/xray/domain)
IPVS=$(cat /etc/xray/ipvps)

print_success "Core Xray Latest Version"
clear
}
sudo curl -s ipinfo.io/city | sudo tee /etc/xray/city
sudo curl -s ipinfo.io/org | cut -d " " -f 2-10 | sudo tee /etc/xray/isp

print_install "Installing Packet Configuration"

sudo wget -q -O /etc/haproxy/haproxy.cfg "${REPO}ubuntu/haproxy.cfg"
sudo wget -q -O /etc/nginx/conf.d/xray.conf "${REPO}ubuntu/xray.conf"

# Guard domain substitution: only run if domain is set and files exist
# OLD:
# sudo sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
# sudo sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

# NEW:
if [ -n "${domain:-}" ]; then
	if [ -f /etc/haproxy/haproxy.cfg ]; then
		sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg || true
	fi
	if [ -f /etc/nginx/conf.d/xray.conf ]; then
		sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf || true
	fi
fi

sudo curl -s "${REPO}ubuntu/nginx.conf" > /etc/nginx/nginx.conf
cat /etc/xray/xray.crt /etc/xray/xray.key | sudo tee /etc/haproxy/hap.pem

sudo chmod +x /etc/systemd/system/runn.service
sudo rm -rf /etc/systemd/system/xray.service.d

sudo bash -c 'cat > /etc/systemd/system/xray.service <<EOF
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
EOF'

print_success "Configuration Packet"
}

function ssh() {
	clear
	print_install "Installing Password SSH"

	wget -q -O /etc/pam.d/common-password "${REPO}ubuntu/password"
	chmod 700 /etc/pam.d/common-password

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

	# Proper rc-local service + rc.local script (fixed)
	cat >/etc/systemd/system/rc-local.service <<'UNIT'
[Unit]
Description=/etc/rc.local Compatibility
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
UNIT

	cat >/etc/rc.local <<'EOF'
#!/bin/bash
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
EOF

	chmod +x /etc/rc.local

	echo -e "[INFO] Enabling and starting rc-local service..."
	systemctl enable rc-local >/dev/null 2>&1 || true
	systemctl start rc-local.service >/dev/null 2>&1 || true

	echo -e "[INFO] Configuring rc.local to disable IPv6 on startup..."
	# ensure line exists once
	grep -qxF 'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local 2>/dev/null || \
		sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local >/dev/null 2>&1 || true

	ln -fs /usr/share/zoneinfo/Africa/Nairobi /etc/localtime
	sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

	print_success "Password SSH"
}

function udp_mini() {
clear
print_install "Installing Service Limit IP & Quota"
wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${REPO}ubuntu/udp-mini"
chmod +x /usr/local/kyt/udp-mini

for i in 1 2 3; do
wget -q -O /etc/systemd/system/udp-mini-${i}.service "${REPO}ubuntu/udp-mini-${i}.service"
systemctl disable udp-mini-${i}
systemctl stop udp-mini-${i}
systemctl enable udp-mini-${i}
systemctl start udp-mini-${i}
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
wget -q -O /etc/ssh/sshd_config "${REPO}ubuntu/sshd"
chmod 700 /etc/ssh/sshd_config
systemctl restart ssh
systemctl status ssh --no-pager
print_success "SSHD"
}

function ins_dropbear() {
clear
print_install "Installing Dropbear"
apt-get install dropbear -y >/dev/null 2>&1
wget -q -O /etc/default/dropbear "${REPO}ubuntu/dropbear.conf"
chmod +x /etc/default/dropbear
systemctl restart dropbear
systemctl status dropbear --no-pager
print_success "Dropbear"
}

clear
function ins_vnstat() {
clear
print_install "Installing Vnstat"
apt -y install vnstat > /dev/null 2>&1
systemctl restart vnstat
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.8.tar.gz -O /tmp/vnstat-2.8.tar.gz
tar zxvf /tmp/vnstat-2.8.tar.gz -C /tmp
cd /tmp/vnstat-2.8
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
systemctl restart vnstat
systemctl status vnstat --no-pager
rm -f /tmp/vnstat-2.8.tar.gz
rm -rf /tmp/vnstat-2.8
print_success "Vnstat"
}

function ins_openvpn() {
clear
print_install "Installing OpenVPN"
wget "${REPO}ubuntu/openvpn" -O /tmp/openvpn && chmod +x /tmp/openvpn && /tmp/openvpn
systemctl restart openvpn
print_success "OpenVPN"
}

function ins_backup() {
clear
print_install "Installing Backup Server"
apt install rclone -y
printf "q\n" | rclone config
mkdir -p /root/.config/rclone
wget -O /root/.config/rclone/rclone.conf "${REPO}ubuntu/rclone.conf"
cd /tmp
git clone https://github.com/magnific0/wondershaper.git
cd wondershaper
sudo make install
cd
rm -rf /tmp/wondershaper
echo > /home/limit
apt install msmtp-mta ca-certificates bsd-mailx -y

cat <<EOF >/etc/msmtprc
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

function ins_swab() {
clear
print_install "Installing Swap 1 G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*\"v(.*)\".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v${gotop_latest}_linux_amd64.deb"
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
dd if=/dev/zero of=/swapfile bs=1024 count=1048576
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile swap swap defaults 0 0' /etc/fstab
chronyd -q 'server 0.id.pool.ntp.org iburst'
chronyc sourcestats -v
chronyc tracking -v
wget "${REPO}ubuntu/bbr.sh" -O /tmp/bbr.sh && chmod +x /tmp/bbr.sh && /tmp/bbr.sh
print_success "Swap 1 G"
}

function ins_Fail2ban() {
clear
print_install "Installing Fail2ban"
apt -y install fail2ban > /dev/null 2>&1
systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl status fail2ban --no-pager

if [ -d '/usr/local/ddos' ]; then
echo; echo; echo "Please un-install the previous version first"
exit 0
else
mkdir /usr/local/ddos
fi

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

function ins_restart() {
clear
print_install "Restarting All Packet"
systemctl restart nginx openvpn ssh dropbear fail2ban vnstat haproxy cron ws
systemctl daemon-reload
systemctl enable --now nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws fail2ban

history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/openvpn /root/key.pem /root/cert.pem
print_success "All Packet"
}

function menu() {
clear
print_install "Installing Menu Packet"
wget "${REPO}ubuntu/menu.zip"
unzip menu.zip
chmod +x menu/*
mv menu/* /usr/local/sbin
rm -rf menu menu.zip
}

function profile() {
clear
# Setup .profile to auto-launch menu
cat >/root/.profile <<'EOF'
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

# Cron jobs
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

echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray

systemctl restart cron

# Daily reboot value
echo "5" >/home/daily_reboot

# rc-local service for legacy startup tasks
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

# Ensure no-login shells
echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells

# rc.local script
cat >/etc/rc.local <<'EOF'
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
chmod +x /etc/rc.local

# Set AM/PM for future use (optional)
AUTOREB=$(cat /home/daily_reboot)
SETT=11
if [ "$AUTOREB" -gt "$SETT" ]; then
TIME_DATE="PM"
else
TIME_DATE="AM"
fi

print_success "Menu Packet"
}

# New: write a health-check script and systemd timer to auto-fix services
write_health_check() {
cat > /usr/local/bin/spider-health.sh <<'HEALTH'
#!/usr/bin/env bash
LOG="/var/log/spider-health.log"
exec >>"$LOG" 2>&1
echo "==== spider-health run: $(date) ===="

# services to monitor (key names); mapped to package name fallback
declare -A PKG_MAP=(
  [nginx]=nginx
  [haproxy]=haproxy
  [openvpn]=openvpn
  [ssh]=openssh-server
  [dropbear]=dropbear
  [ws]=ws
  [xray]=xray
  [netfilter-persistent]=netfilter-persistent
  [cron]=cron
  [fail2ban]=fail2ban
)

# common unit name alternatives
declare -A UNIT_ALTS=(
  [nginx]="nginx.service"
  [haproxy]="haproxy.service"
  [openvpn]="openvpn.service openvpn@server.service openvpn-server@server.service"
  [ssh]="ssh.service sshd.service"
  [dropbear]="dropbear.service"
  [ws]="ws.service"
  [xray]="xray.service xray"
  [netfilter-persistent]="netfilter-persistent.service"
  [cron]="cron.service"
  [fail2ban]="fail2ban.service"
)

# helper to restart/enable a unit
try_fix_unit() {
  local unit="$1"
  echo "Checking unit: $unit"
  if systemctl list-unit-files --type=service | grep -Fq "$unit"; then
    if systemctl is-active --quiet "$unit"; then
      echo "$unit is active"
      return 0
    fi
    echo "$unit inactive, attempting restart..."
    systemctl daemon-reload
    systemctl restart "$unit" && systemctl enable "$unit" && { echo "Restarted and enabled $unit"; return 0; } || echo "Restart failed for $unit"
    # fetch recent logs
    echo "Recent journal for $unit:"
    journalctl -u "$unit" -n 60 --no-pager || true
    return 1
  else
    echo "Unit $unit not found"
    return 2
  fi
}

# test specific configs
test_and_fix_config() {
  if command -v nginx >/dev/null 2>&1; then
    if nginx -t >/dev/null 2>&1; then
      echo "nginx config ok"
    else
      echo "nginx config failed, writing journal and trying to restore default minimal config"
      journalctl -u nginx -n 60 --no-pager || true
      # attempt minimal safe config if available
      if [ -f /etc/nginx/nginx.conf ]; then
        cp -f /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak || true
      fi
      # try to reload safely
      systemctl restart nginx || true
    fi
  fi

  if command -v haproxy >/dev/null 2>&1; then
    if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
      echo "haproxy config ok"
    else
      echo "haproxy config failed"
      journalctl -u haproxy -n 60 --no-pager || true
      systemctl restart haproxy || true
    fi
  fi
}

# iterate and fix
for key in "${!UNIT_ALTS[@]}"; do
  echo "---- processing: $key ----"
  fixed=0
  for unit in ${UNIT_ALTS[$key]}; do
    try_fix_unit "$unit"
    res=$?
    if [ $res -eq 0 ]; then
      fixed=1
      break
    elif [ $res -eq 2 ]; then
      # unit not found, continue to next alternative
      continue
    fi
  done

  if [ $fixed -eq 0 ]; then
    # attempt to install package if mapped and unit not found or failed
    pkg="${PKG_MAP[$key]:-}"
    if [ -n "$pkg" ]; then
      if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "$pkg not installed, attempting apt-get install -y $pkg"
        apt-get update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || true
        # try starting mapped unit names again
        for unit in ${UNIT_ALTS[$key]}; do
          try_fix_unit "$unit" && fixed=1 && break
        done
      else
        echo "Package $pkg installed but unit still inactive"
      fi
    fi
  fi
done

# extra config tests
test_and_fix_config

echo "==== spider-health finished: $(date) ===="
HEALTH
chmod +x /usr/local/bin/spider-health.sh
}

write_health_unit() {
# systemd service
cat > /etc/systemd/system/spider-health.service <<'UNIT'
[Unit]
Description=Spider health check and auto-fix
Documentation=man:systemd
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/spider-health.sh
Nice=10
StandardOutput=journal
StandardError=journal
UNIT

# systemd timer (run every 5 minutes)
cat > /etc/systemd/system/spider-health.timer <<'TIMER'
[Unit]
Description=Run spider-health every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now spider-health.timer
# run once immediately to fix current state
/usr/local/bin/spider-health.sh || true
}

# Insert call into enable_services to ensure it is created and enabled
function enable_services() {
clear
print_install "Enable Service"
systemctl daemon-reload
systemctl start netfilter-persistent
systemctl enable --now rc-local cron netfilter-persistent
systemctl restart nginx xray cron haproxy || true

# ensure health-check script and timer are present and active
write_health_check
write_health_unit

# call existing verification helper if present
if declare -f verify_and_enable_services >/dev/null 2>&1; then
    verify_and_enable_services || true
fi

print_success "Enable Service"
clear
}

# Replace the duplicated final hostname setting with a single safe line:
if [[ -n "${ADMIN_NAME:-}" ]]; then
  sudo hostnamectl set-hostname "${ADMIN_NAME}" >/dev/null 2>&1 || true
fi

# Make final reboot prompt safe: call only when script executed directly
final_message_and_reboot() {
	# Friendly message
	echo
	echo -e "${Green}haappy tunnellin${NC}"
	# Prompt and wait for any key
	read -n 1 -s -r -p "Press any button to reboot..." || true
	echo
	# Flush filesystem buffers
	sync
	# Attempt a clean reboot
	if command -v systemctl >/dev/null 2>&1; then
		systemctl reboot
	else
		reboot
	fi
}

# NEW: call only when script run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	final_message_and_reboot || true
fi
