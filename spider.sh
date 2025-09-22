#!/usr/bin/env bash
set -o errexit
set -o pipefail

# Colors / symbols
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

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
	echo "This installer must be run as root. Exiting." >&2
	exit 1
fi

# Non-interactive apt
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# Minimal package update (no sudo because script runs as root)
apt-get update -y || true
apt-get upgrade -y || true
apt-get install -y --no-install-recommends figlet || true

# ---------- helpers available early ----------
# Wait for apt/dpkg locks
apt_wait_lock() {
	local n=0
	while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
	   || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
	   || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
		n=$((n+1))
		if [ "$n" -gt 30 ]; then
			printf "%b\n" "${ERROR} apt/dpkg lock held too long. Aborting." >&2
			return 1
		fi
		printf "%b\n" "${YELLOW} Waiting for apt/dpkg lock... (${n})${FONT}"
		sleep 2
	done
	return 0
}

# Retry wrapper
retry_cmd() {
	local tries=4 wait=3 i=0
	until "$@"; do
		i=$((i+1))
		if [ "$i" -ge "$tries" ]; then
			printf "%b\n" "${ERROR} Command failed after ${tries} attempts: $*" >&2
			return 1
		fi
		printf "%b\n" "${YELLOW}Retrying: $* (${i}/${tries})${FONT}"
		sleep "$wait"
	done
	return 0
}

# Logging & spinner
LOGFILE="/var/log/spider-install.log"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
exec 3>>"$LOGFILE"

log() { printf "[%s] %s %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" "$2" >&3; }

spinner_start() {
	local msg="${1:-Working...}"
	printf "%s " "$msg"
	(
		i=0
		chars='/-\|'
		while :; do
			printf "\b${chars:i++%${#chars}:1}"
			sleep 0.12
		done
	) &
	SPINNER_PID=$!
}
spinner_stop() {
	if [ -n "${SPINNER_PID:-}" ]; then
		kill "$SPINNER_PID" >/dev/null 2>&1 || true
		wait "$SPINNER_PID" 2>/dev/null || true
		unset SPINNER_PID
		printf "\b done.\n"
	fi
}

# ---------- UI ----------
typing_banner() {
	local text="$1" color="$2"
	printf "%b" "${color}\e[1m"
	for ((i=0;i<${#text};i++)); do
		printf "%s" "${text:i:1}"
		sleep 0.03
	done
	printf "%b\n" "${NC}"
}

# Show greeting
clear
echo -e "\e[92m$(figlet -f small -w 80 'WELCOME TO SPIDER STORE')\e[0m"
typing_banner "Programmer: SPIDER" "$Green"
typing_banner "©2024: STABLE EDITION" "$Green"
typing_banner "⚠️ ATTENTION!" "$RED"
typing_banner "This is the Original script; any cloned version is pirated. t.me/spid_3r" "$BLUE"
typing_banner "Happy Tunneling!" "$YELLOW"

# Basic environment detection
IP="$(curl -sS ipv4.icanhazip.com || true)"
if [ -z "$IP" ]; then
	printf "%b\n" "${ERROR} IP Address not detected"
	exit 1
fi

# detect OS identifiers early (will be refined)
OS_ID="$(. /etc/os-release && echo "${ID:-}" )"
OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-}" | tr -d '"')"
OS_CODENAME="$(lsb_release -cs 2>/dev/null || true)"
OS_VERSION_ID="$(. /etc/os-release && echo "${VERSION_ID:-}" )"
OS_ID_LIKE="$(. /etc/os-release && echo "${ID_LIKE:-}" )"

printf "%b\n" "${Green}  » Your OS: ${OS_NAME} (${OS_ID})${FONT}"
printf "%b\n" "${Green}  » IP Address: ${Green}${IP}${NC}"

# NEW: detect package manager and set install/update/upgrade wrappers
detect_pkgmgr_and_platform() {
	# refresh OS_* in case not set
	OS_ID="$(. /etc/os-release && echo "${ID:-}" )"
	OS_ID_LIKE="$(. /etc/os-release && echo "${ID_LIKE:-}" )"
	OS_VERSION_ID="$(. /etc/os-release && echo "${VERSION_ID:-}" )"
	OS_CODENAME="$(lsb_release -cs 2>/dev/null || true)"

	PKGMGR="apt"
	case 1 in
		$(command -v apt-get >/dev/null 2>&1 && echo 1) ) PKGMGR="apt";;
		$(command -v dnf >/dev/null 2>&1 && echo 1) ) PKGMGR="dnf";;
		$(command -v yum >/dev/null 2>&1 && echo 1) ) PKGMGR="yum";;
		$(command -v apk >/dev/null 2>&1 && echo 1) ) PKGMGR="apk";;
		$(command -v zypper >/dev/null 2>&1 && echo 1) ) PKGMGR="zypper";;
		$(command -v pacman >/dev/null 2>&1 && echo 1) ) PKGMGR="pacman";;
		* ) PKGMGR="apt";;
	esac

	# set command templates
	case "$PKGMGR" in
		apt)
			UPDATE_CMD="apt-get update -y"
			INSTALL_CMD="apt-get install -y --no-install-recommends"
			UPGRADE_CMD="apt-get -y upgrade"
			UPGRADE_PKG_CMD="apt-get install --only-upgrade -y"
			;;
		dnf)
			UPDATE_CMD="dnf makecache -y || true"
			INSTALL_CMD="dnf install -y"
			UPGRADE_CMD="dnf -y upgrade"
			UPGRADE_PKG_CMD="dnf -y upgrade"
			;;
		yum)
			UPDATE_CMD="yum makecache -y || true"
			INSTALL_CMD="yum install -y"
			UPGRADE_CMD="yum -y update"
			UPGRADE_PKG_CMD="yum -y update"
			;;
		apk)
			UPDATE_CMD="apk update"
			INSTALL_CMD="apk add --no-cache"
			UPGRADE_CMD="apk upgrade"
			UPGRADE_PKG_CMD="apk upgrade"
			;;
		zypper)
			UPDATE_CMD="zypper refresh"
			INSTALL_CMD="zypper install -y"
			UPGRADE_CMD="zypper update -y"
			UPGRADE_PKG_CMD="zypper update -y"
			;;
		pacman)
			UPDATE_CMD="pacman -Sy --noconfirm"
			INSTALL_CMD="pacman -S --noconfirm"
			UPGRADE_CMD="pacman -Syu --noconfirm"
			UPGRADE_PKG_CMD="pacman -S --noconfirm"
			;;
		*)
			UPDATE_CMD="apt-get update -y"
			INSTALL_CMD="apt-get install -y --no-install-recommends"
			UPGRADE_CMD="apt-get -y upgrade"
			UPGRADE_PKG_CMD="apt-get install --only-upgrade -y"
			;;
	esac

	log INFO "Detected PKGMGR=${PKGMGR}, OS_ID=${OS_ID}, OS_ID_LIKE=${OS_ID_LIKE}, VERSION_ID=${OS_VERSION_ID}"
}

# Wrapper to run update using the detected manager
run_update() {
	apt_wait_lock || true
	retry_cmd bash -c "${UPDATE_CMD}" || true
}

# Wrapper to install packages with the detected manager (best-effort)
pkg_install() {
	# accepts many args
	apt_wait_lock || true
	if [ "$PKGMGR" = "apt" ]; then
		DEBIAN_FRONTEND=noninteractive retry_cmd bash -c "${INSTALL_CMD} $*" || true
	else
		retry_cmd bash -c "${INSTALL_CMD} $*" || true
	fi
}

# Wrapper to upgrade a single package (best-effort)
pkg_upgrade_pkg() {
	apt_wait_lock || true
	if [ "$PKGMGR" = "apt" ]; then
		DEBIAN_FRONTEND=noninteractive retry_cmd bash -c "${UPGRADE_PKG_CMD} $*" || true
	else
		retry_cmd bash -c "${UPGRADE_PKG_CMD} $*" || true
	fi
}

# Ensure detection runs now
detect_pkgmgr_and_platform

# ---------- prompts (only these three) ----------
read -s -p "$(echo -e ${Green}Enter admin password:${NC} )" ADMIN_PASS
echo
if [ "${ADMIN_PASS}" != "wantam" ]; then
	printf "%b\n" "${RED}Incorrect password. Installation aborted.${NC}"
	exit 1
fi

read -p "$(echo -e ${Green}Enter Your name:${NC} )" ADMIN_NAME
: "${ADMIN_NAME:=admin}"
export ADMIN_NAME

# Domain selection: only required interactive step for domain
REPO="https://raw.githubusercontent.com/spider660/Lau_Op/main/"
install_domain() {
	printf "%b\n" "Please select domain option:"
	printf "1) Use your own domain (recommended)\n2) Use random domain\n"
	read -p "Select 1-2 (default Random): " host
	if [[ "$host" == "1" ]]; then
		read -p "Input Domain: " host1
		if [ -n "$host1" ]; then
			echo "$host1" > /etc/xray/domain
			echo "$host1" > /root/domain
		else
			printf "%b\n" "${YELLOW}No domain entered. Using random/subdomain later.${NC}"
		fi
	else
		# try to run cf.sh from repo, best-effort
		if retry_cmd curl -fsSL "${REPO}ubuntu/cf.sh" -o /root/cf.sh; then
			chmod +x /root/cf.sh
			bash /root/cf.sh || true
			rm -f /root/cf.sh
		fi
	fi
}

install_domain

# ---------- directories and perms ----------
ensure_dirs_and_permissions() {
	log INFO "Ensuring directories"
	local dirs=(/etc/xray /var/log/xray /var/www/html /usr/local/sbin /usr/bin /etc/haproxy /etc/nginx/conf.d /etc/systemd/system /root/.acme.sh /etc/ssh /var/lib/kyt /etc/kyt /etc/user-create /usr/local/kyt)
	for d in "${dirs[@]}"; do
		[ -d "$d" ] || mkdir -p "$d" 2>/dev/null || log ERROR "Failed to create $d"
	done
	touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log || true
	chown -R www-data:www-data /var/log/xray 2>/dev/null || true
	chmod -R 755 /usr/local/sbin /usr/bin /var/www/html 2>/dev/null || true
}

ensure_dirs_and_permissions

# ---------- NEW: preflight checks and service upgrades ----------
preflight_check() {
	log INFO "Running preflight checks"

	# Ensure minimal commands exist; try to install missing ones non-interactively
	local need=(lsb_release fuser gpg systemctl curl wget unzip iptables iproute2)
	local miss=()
	for cmd in "${need[@]}"; do
		if ! command -v "$cmd" >/dev/null 2>&1; then
			miss+=("$cmd")
		fi
	done

	if [ "${#miss[@]}" -gt 0 ]; then
		log INFO "Installing missing tools: ${miss[*]}"
		apt_wait_lock || true
		DEBIAN_FRONTEND=noninteractive retry_cmd apt-get install -y --no-install-recommends "${miss[@]}" || true
	fi

	# Basic network checks (DNS + outbound)
	if ! curl -fsS https://api.ipify.org >/dev/null 2>&1; then
		log ERROR "Outbound HTTP(s) seems blocked — some operations may fail"
	fi

	# Check port 80 availability (ACME)
	if ss -ltn "( sport = :80 )" | grep -q LISTEN; then
		log INFO "Port 80 in use; ACME standalone may fail (will try to stop webservers during issuance)"
	else
		log INFO "Port 80 appears free"
	fi

	# Make sure apt lists are fresh
	apt_wait_lock || true
	retry_cmd apt-get update -y || true

	log INFO "Preflight checks complete"
}

service_upgrade() {
	log INFO "Attempting to upgrade key services (best-effort)"

	local pkgs=(nginx haproxy openvpn xray dropbear fail2ban)
	for p in "${pkgs[@]}"; do
		# Only try to upgrade if package is installed via dpkg or present in package database
		if ( [ "$PKGMGR" = "apt" ] && dpkg -s "$p" >/dev/null 2>&1 ) || \
		   ( [ "$PKGMGR" != "apt" ] && command -v "$PKGMGR" >/dev/null 2>&1 ); then
			log INFO "Upgrading package $p"
			pkg_upgrade_pkg "$p" || true
			# restart unit(s) matching common names
			for unit in "$p" "${p}.service" "${p}@server.service" "${p}-server.service"; do
				if systemctl list-unit-files --type=service | grep -q "^${unit}$"; then
					systemctl restart "$unit" >/dev/null 2>&1 || true
					systemctl enable "$unit" >/dev/null 2>&1 || true
				fi
			done
		else
			log INFO "Package $p not found/managed by this PKGMGR; skipping upgrade"
		fi
	done

	# Do a safe upgrade
	run_update || true
	if [ "$PKGMGR" = "apt" ]; then
		retry_cmd apt-get -y upgrade || true
	else
		retry_cmd bash -c "${UPGRADE_CMD}" || true
	fi

	log INFO "Service upgrade attempts complete"
}

# Call new checks before heavy installs
preflight_check || true
service_upgrade || true

# ---------- dependency installer ----------
ensure_dependencies() {
	log INFO "Installing dependencies (best-effort)"
	run_update || true

	COMMON_PKGS=(
		apt-transport-https ca-certificates curl wget gnupg lsb-release software-properties-common
		build-essential unzip zip sudo dnsutils lsof htop net-tools iproute2 iptables iptables-persistent
		netfilter-persistent cron chrony ntpdate rsyslog bash-completion jq git sed gawk coreutils openssl
		ruby figlet pwgen make gcc g++ python3-pip p7zip-full netcat socat gnupg2 gpg rsync bc
	)

	# adapt package names for non-apt systems where necessary
	if [ "$PKGMGR" = "apk" ]; then
		# Alpine package name differences (best-effort minimal set)
		COMMON_PKGS=(ca-certificates curl wget gnupg openssh-client bash coreutils make gcc g++ python3 py3-pip tzdata)
	fi

	pkg_install "${COMMON_PKGS[@]}" || true

	# minimal attempt to ensure haproxy/nginx/openvpn (use pkg_install)
	pkg_install nginx haproxy openvpn netfilter-persistent iptables-persistent || true

	# enable time sync if available
	if command -v systemctl >/dev/null 2>&1; then
		systemctl enable --now chrony >/dev/null 2>&1 || true
	fi
	log INFO "Dependencies installed"
}

install_os_specific() {
	log INFO "Running OS-specific installs"
	OS_ID="$(. /etc/os-release && echo "${ID:-}" )"
	OS_CODENAME="$(lsb_release -cs 2>/dev/null || true)"

	# Ensure basic tooling to operate on repos
	apt_wait_lock || true
	retry_cmd apt-get install -y --no-install-recommends lsb-release gnupg dirmngr apt-transport-https || true

	if [ "$OS_ID" = "debian" ]; then
		log INFO "Applying Debian-specific configuration for ${OS_CODENAME}"
		# Add HAProxy Debian repo (best-effort)
		apt_wait_lock || true
		retry_cmd curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg || true
		echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net ${OS_CODENAME}-backports main" >/etc/apt/sources.list.d/haproxy.list 2>/dev/null || true
		apt_wait_lock || true
		retry_cmd apt-get update -y || true
		retry_cmd apt-get install -y --no-install-recommends haproxy || true

	elif [ "$OS_ID" = "ubuntu" ]; then
		log INFO "Applying Ubuntu-specific configuration for ${OS_CODENAME}"
		apt_wait_lock || true
		retry_cmd apt-get install -y --no-install-recommends software-properties-common || true
		# Try PPA fallback for haproxy
		if command -v add-apt-repository >/dev/null 2>&1; then
			retry_cmd add-apt-repository -y ppa:vbernat/haproxy || true
			apt_wait_lock || true
			retry_cmd apt-get update -y || true
		fi
		retry_cmd apt-get install -y --no-install-recommends haproxy || true

	else
		log INFO "Unknown distro (${OS_ID}); skipping OS-specific package installs"
	fi

	# Ensure common services are enabled if present
	for svc in nginx haproxy openvpn xray; do
		if systemctl list-unit-files --type=service | grep -Fq "${svc}.service"; then
			systemctl enable --now "${svc}.service" >/dev/null 2>&1 || true
		fi
	done

	log INFO "OS-specific installs complete"
}

# Call the fixed function and then run OS-specific adjustments
ensure_dependencies
install_os_specific

# NEW: ensure core packages/services are present, enabled and started
ensure_services_installed_and_active() {
	log INFO "Ensuring core services/packages are installed and active (best-effort)"

	# map service keys to apt package names (fallback to same name)
	declare -A SERVICE_PKG=(
		[nginx]=nginx
		[haproxy]=haproxy
		[openvpn]=openvpn
		[xray]=xray
		[dropbear]=dropbear
		[fail2ban]=fail2ban
		[cron]=cron
		[netfilter-persistent]=netfilter-persistent
		[ws]=ws
	)

	# unit name alternatives per service
	declare -A UNIT_ALTS2=(
		[nginx]="nginx.service"
		[haproxy]="haproxy.service"
		[openvpn]="openvpn.service openvpn@server.service openvpn-server@server.service"
		[xray]="xray.service"
		[dropbear]="dropbear.service"
		[fail2ban]="fail2ban.service"
		[cron]="cron.service"
		[netfilter-persistent]="netfilter-persistent.service"
		[ws]="ws.service"
	)

	for svc in "${!SERVICE_PKG[@]}"; do
		pkg="${SERVICE_PKG[$svc]}"
		# attempt to install package if not present
		if ! dpkg -s "$pkg" >/dev/null 2>&1; then
			log INFO "Package $pkg not found; attempting install (best-effort)"
			apt_wait_lock || true
			DEBIAN_FRONTEND=noninteractive retry_cmd apt-get install -y --no-install-recommends "$pkg" || log ERROR "Install failed for $pkg"
		else
			log INFO "Package $pkg already installed"
		fi

		# enable & start the first matching unit alternative
		for unit in ${UNIT_ALTS2[$svc]}; do
			if systemctl list-unit-files --type=service | grep -Fq "^${unit}$"; then
				log INFO "Enabling & starting unit $unit"
				systemctl daemon-reload >/dev/null 2>&1 || true
				systemctl enable --now "$unit" >/dev/null 2>&1 || log ERROR "Failed to enable/start $unit"
				break
			fi
		done
	done

	# final sweep: restart common services to ensure config reload
	for svc in nginx haproxy xray openvpn dropbear fail2ban cron; do
		if systemctl list-unit-files --type=service | grep -Fq "${svc}.service"; then
			systemctl restart "${svc}.service" >/dev/null 2>&1 || true
		fi
	done

	log INFO "Core service ensure complete"
}

# Call it to make services present and active before main installation steps
ensure_services_installed_and_active

# ---------- utility functions (print messages) ----------
print_install() { printf "%b\n" "${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}\n${YELLOW} » $1 ${FONT}\n${green} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ${FONT}"; sleep 1; }
print_success() { printf "%b\n" "${Green} » $1 installed successfully${NC}"; sleep 1; }
print_error() { printf "%b\n" "${ERROR} $1${NC}"; }

# ---------- essential installers (kept compact and safe) ----------

install_ssl() {
	print_install "Installing SSL on domain"
	domain="$(cat /root/domain 2>/dev/null || true)"
	if [ -z "$domain" ]; then
		print_error "No domain configured; skipping SSL issuance"
		return 0
	fi

	# stop common web servers
	for svc in nginx apache2 httpd; do
		systemctl is-active --quiet "$svc" && systemctl stop "$svc" >/dev/null 2>&1 || true
	done

	rm -rf /root/.acme.sh
	mkdir -p /root/.acme.sh
	if ! retry_cmd curl -fsSL https://get.acme.sh -o /root/.acme.sh/acme.sh; then
		print_error "Failed to download acme.sh"
		return 1
	fi
	chmod +x /root/.acme.sh/acme.sh
	/root/.acme.sh/acme.sh --install --auto-upgrade --home /root/.acme.sh >/dev/null 2>&1 || true
	/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
	/root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 >/dev/null 2>&1 || { print_error "acme.sh failed to issue certificate"; return 1; }
	/root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc >/dev/null 2>&1 || { print_error "Installing certificate failed"; return 1; }
	chmod 600 /etc/xray/xray.key || true
	print_success "SSL Certificate"
}

install_xray() {
	print_install "Installing core Xray"
	mkdir -p /run/xray
	chown www-data:www-data /run/xray || true
	# Best-effort: use official installer if available
	if retry_cmd curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/xray-inst.sh; then
		bash /tmp/xray-inst.sh @ install -u www-data || true
	fi
	# configuration placeholders
	retry_cmd curl -fsSL "${REPO}ubuntu/config.json" -o /etc/xray/config.json || true
	retry_cmd curl -fsSL "${REPO}ubuntu/runn.service" -o /etc/systemd/system/runn.service || true
	print_success "Core Xray"
}

install_common_configs() {
	print_install "Installing common configuration files"
	# use curl directly (script is root)
	retry_cmd curl -fsSL "${REPO}ubuntu/haproxy.cfg" -o /etc/haproxy/haproxy.cfg || true
	retry_cmd curl -fsSL "${REPO}ubuntu/xray.conf" -o /etc/nginx/conf.d/xray.conf || true
	# replace domain tokens if domain present
	domain="$(cat /root/domain 2>/dev/null || true)"
	if [ -n "$domain" ]; then
		[ -f /etc/haproxy/haproxy.cfg ] && sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg || true
		[ -f /etc/nginx/conf.d/xray.conf ] && sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf || true
	fi
	# combine certs for haproxy if present
	if [ -f /etc/xray/xray.crt ] && [ -f /etc/xray/xray.key ]; then
		cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem || true
	fi
	print_success "Configuration files"
}

setup_rc_local() {
	# safe rc-local systemd unit and script
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
# rc.local tasks (idempotent)
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 || true
exit 0
EOF
	chmod +x /etc/rc.local
	systemctl daemon-reload || true
	systemctl enable --now rc-local.service >/dev/null 2>&1 || true
}

install_ssh_password() {
	print_install "Configuring password auth and PAM"
	retry_cmd curl -fsSL "${REPO}ubuntu/password" -o /etc/pam.d/common-password || true
	chmod 600 /etc/pam.d/common-password || true
	# noninteractive keyboard config
	DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive keyboard-configuration >/dev/null 2>&1 || true
	sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config || true
	systemctl reload ssh || true
	print_success "SSH configuration"
}

# ---------- health check and auto-fix ----------
write_health_check() {
	cat >/usr/local/bin/spider-health.sh <<'HEALTH'
#!/usr/bin/env bash
LOG="/var/log/spider-health.log"
exec >>"$LOG" 2>&1
echo "==== spider-health run: $(date) ===="
for svc in nginx haproxy openvpn ssh dropbear xray cron fail2ban netfilter-persistent; do
  if systemctl list-unit-files --type=service | grep -q "^${svc}.service"; then
    if ! systemctl is-active --quiet "${svc}.service"; then
      systemctl restart "${svc}.service" >/dev/null 2>&1 || true
      systemctl enable "${svc}.service" >/dev/null 2>&1 || true
    fi
  fi
done
echo "==== spider-health finished: $(date) ===="
HEALTH
	chmod +x /usr/local/bin/spider-health.sh
	cat >/etc/systemd/system/spider-health.timer <<'TIMER'
[Unit]
Description=Run spider-health every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
TIMER
	cat >/etc/systemd/system/spider-health.service <<'UNIT'
[Unit]
Description=Spider health check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/spider-health.sh
UNIT
	systemctl daemon-reload || true
	systemctl enable --now spider-health.timer >/dev/null 2>&1 || true
}

# ---------- enable services ----------
enable_services() {
	print_install "Enabling services"
	systemctl daemon-reload || true
	for svc in nginx haproxy xray rc-local dropbear openvpn cron netfilter-persistent ws fail2ban; do
		if systemctl list-unit-files --type=service | grep -q "^${svc}.service"; then
			systemctl enable --now "${svc}.service" >/dev/null 2>&1 || true
		fi
	done
	write_health_check
	print_success "Services enabled"
}

# ---------- main flow: run installers (best-effort, auto) ----------
main_install() {
	install_ssh_password || true
	setup_rc_local || true
	install_xray || true
	install_ssl || true
	install_common_configs || true
	enable_services || true
	# install menu if present
	if retry_cmd curl -fsSL "${REPO}ubuntu/menu.zip" -o /tmp/menu.zip; then
		cd /tmp
		unzip -o menu.zip >/dev/null 2>&1 || true
		chmod +x menu/* 2>/dev/null || true
		mv -f menu/* /usr/local/sbin/ 2>/dev/null || true
		rm -rf /tmp/menu* || true
	fi
}

main_install

# ---------- finalize ----------
# set hostname if provided
if [ -n "${ADMIN_NAME:-}" ]; then
	hostnamectl set-hostname "${ADMIN_NAME}" >/dev/null 2>&1 || true
fi

final_message_and_reboot() {
	printf "\n%b\n" "${Green}Installation finished. Press any key to reboot...${NC}"
	read -n 1 -s -r || true
	sync
	if command -v systemctl >/dev/null 2>&1; then
		systemctl reboot
	else
		reboot
	fi
}

# Only prompt for reboot when script run directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	final_message_and_reboot || true
fi
