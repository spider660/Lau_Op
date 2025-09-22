#!/bin/bash
set -euo pipefail

REPO_GIT="https://github.com/spider660/Lau_Op.git"
REPO_RAW="https://raw.githubusercontent.com/spider660/Lau_Op/main"
WORKDIR="/tmp/spider-update-$$"
BACKUP_DIR="/root/spider-backup-$(date +%Y%m%d-%H%M%S)"
LOGFILE="/var/log/spider-update.log"

mkdir -p "$WORKDIR"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

# require root
if [ "$(id -u)" -ne 0 ]; then
  echo "This updater must be run as root."
  exit 1
fi

# ensure required tools
for cmd in git rsync curl unzip wget; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "Installing missing tool: $cmd"
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "$cmd" >/dev/null 2>&1 || { log "Failed to install $cmd"; }
  fi
done

# small spinner for user feedback
spinner_start() {
  local pid=$1
  local delay=0.08
  tput civis 2>/dev/null || true
  while kill -0 "$pid" >/dev/null 2>&1; do
    for c in / - \\ \|; do
      printf "\r  Updating... %s" "$c"
      sleep "$delay"
    done
  done
  printf "\r  Updating... done\n"
  tput cnorm 2>/dev/null || true
}

# backup common install locations (best-effort)
log "Creating backup to $BACKUP_DIR (this may be large)"
mkdir -p "$BACKUP_DIR"
BACKUP_PATHS=(
  /usr/local/sbin
  /usr/local/bin
  /usr/bin
  /etc/xray
  /etc/haproxy
  /etc/nginx
  /etc/systemd/system
  /var/www/html
  /etc/ssh
)
tar -czf "$BACKUP_DIR/backup.tar.gz" --warning=no-file-changed --absolute-names "${BACKUP_PATHS[@]}" >/dev/null 2>&1 || \
  log "Warning: some backup paths may not exist; continuing"

# fetch repo (prefer git)
log "Cloning repository to $WORKDIR"
if git ls-remote "$REPO_GIT" >/dev/null 2>&1; then
  git clone --depth=1 "$REPO_GIT" "$WORKDIR" >/dev/null 2>&1 &
  spinner_start $!
else
  log "Git clone failed, falling back to zip download"
  wget -q -O "$WORKDIR/repo.zip" "https://github.com/spider660/Lau_Op/archive/refs/heads/main.zip"
  unzip -q "$WORKDIR/repo.zip" -d "$WORKDIR"
  # normalize path to folder
  if [ -d "$WORKDIR/Lau_Op-main" ]; then
    mv "$WORKDIR/Lau_Op-main"/* "$WORKDIR/"
    rmdir "$WORKDIR/Lau_Op-main" || true
  fi
fi

# Determine source dir for files to sync:
SRC="$WORKDIR"
# If repository has an 'ubuntu' folder with deployable content, use it
if [ -d "$WORKDIR/ubuntu" ]; then
  SRC="$WORKDIR/ubuntu"
fi
log "Using source directory: $SRC"

# If repo provides an install script, run it (safer: prefer update mode)
if [ -x "$SRC/install.sh" ]; then
  log "Found install.sh in repo; running install.sh --update (if supported)"
  (cd "$SRC" && bash ./install.sh --update) >/dev/null 2>&1 || log "install.sh executed (non-fatal errors may have occurred)"
elif [ -f "$SRC/spider.sh" ]; then
  log "Found spider.sh in repo; copying core files and executing safe install steps"
  # copy known folders and files using rsync with delete where appropriate
  # Exclude .git and update scripts
  rsync -aHAX --delete --exclude='.git' --exclude='update.sh' --exclude='README*' "$SRC/" / 2>/dev/null || log "rsync to / returned non-fatal error"
else
  # Generic sync: iterate top-level entries and rsync to matching root paths
  log "No install.sh found. Performing heuristic sync of repo content."
  for item in "$SRC"/*; do
    name=$(basename "$item")
    # skip meta files
    case "$name" in
      .git*|README*|update.sh|menu.zip) continue ;;
    esac
    # If item looks like etc or usr or var, rsync into /
    if [[ "$name" == etc || "$name" == usr || "$name" == var || "$name" == etc* || "$name" == usr* || "$name" == var* ]]; then
      log "Syncing $name -> /$name (with --delete)"
      rsync -aHAX --delete --exclude='.git' "$item/" "/$name/" || log "rsync $name non-fatal error"
    else
      # else copy to /usr/local/sbin if it's menu or scripts
      if [[ "$name" =~ menu ]] || [[ "$name" =~ bin ]] || [[ "$name" =~ sbin ]]; then
        log "Syncing $name -> /usr/local/sbin"
        rsync -aHAX --delete --exclude='.git' "$item/" /usr/local/sbin/ || log "rsync $name -> /usr/local/sbin non-fatal error"
      else
        # fallback: copy into /opt/spider/<name>
        mkdir -p /opt/spider/"$name"
        rsync -aHAX --delete --exclude='.git' "$item/" /opt/spider/"$name"/ || log "rsync fallback $name non-fatal error"
      fi
    fi
  done
fi

# update menu if menu.zip present in repo root or ubuntu/menu
if [ -f "$SRC/menu.zip" ]; then
  log "Updating menu from $SRC/menu.zip"
  (cd "$SRC" && unzip -o menu.zip >/dev/null 2>&1 && chmod +x menu/* && mv -f menu/* /usr/local/sbin/ ) || log "menu update failed"
elif [ -f "$WORKDIR/ubuntu/menu.zip" ]; then
  log "Updating menu from $WORKDIR/ubuntu/menu.zip"
  (cd "$WORKDIR/ubuntu" && unzip -o menu.zip >/dev/null 2>&1 && chmod +x menu/* && mv -f menu/* /usr/local/sbin/ ) || log "menu update failed"
fi

# reload systemd and restart common services
log "Reloading systemd daemon and restarting services if present"
systemctl daemon-reload || true
for svc in nginx haproxy xray ws dropbear openvpn cron netfilter-persistent fail2ban; do
  if systemctl list-units --type=service --all | grep -q "^${svc}.service"; then
    log "Restarting $svc"
    systemctl restart "$svc" || log "Failed to restart $svc (non-fatal)"
    systemctl enable "$svc" >/dev/null 2>&1 || true
  fi
done

# apply netfilter-persistent if present
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent reload >/dev/null 2>&1 || netfilter-persistent save >/dev/null 2>&1 || true
fi

# cleanup
rm -rf "$WORKDIR"
log "Update finished. Backup is at $BACKUP_DIR/backup.tar.gz (if created)."

echo
read -n 1 -s -r -p "Press [Enter] to return to menu or exit..."
# try to invoke menu if exists
if command -v menu >/dev/null 2>&1; then
  menu || true
elif [ -x /usr/local/sbin/menu ]; then
  /usr/local/sbin/menu || true
else
  log "Menu entry point not found; exiting."
fi

exit 0