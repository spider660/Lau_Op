#!/bin/bash
set -euo pipefail

# kyt installer - fixed and robust
# Preserves original intent: download bot + kyt, install, write vars, create systemd service

# --- helpers ---
log() { echo -e "\033[36m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m" >&2; }

# --- read system values with safe fallbacks ---
DNS_FILE="/etc/xray/dns"
SLOWDNS_PUB="/etc/slowdns/server.pub"
DOMAIN_FILE="/etc/xray/domain"
NS_FILE="/etc/xray/ns"

DNS_VAL=""
PUB_VAL=""
DOMAIN_VAL=""
NS_VAL=""

if [[ -r "$DNS_FILE" ]]; then
    DNS_VAL="$(tr -d '\n' < "$DNS_FILE")"
fi

if [[ -r "$SLOWDNS_PUB" ]]; then
    PUB_VAL="$(tr -d '\n' < "$SLOWDNS_PUB")"
fi

if [[ -r "$DOMAIN_FILE" ]]; then
    DOMAIN_VAL="$(tr -d '\n' < "$DOMAIN_FILE")"
fi

if [[ -r "$NS_FILE" ]]; then
    NS_VAL="$(tr -d '\n' < "$NS_FILE")"
fi

# fallback for NS if not set
if [[ -z "$NS_VAL" ]]; then
    NS_VAL="${DNS_VAL:-$(hostname -f 2>/dev/null || hostname)}"
fi

# --- install packages ---
log "Updating package lists and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y
apt install -y python3 python3-pip unzip wget git || {
    err "Failed to install required packages"
    exit 1
}

# --- prepare directories ---
INSTALL_DIR="/usr/bin/kyt"
TMPDIR="/tmp/kyt_install_$$"
mkdir -p "$TMPDIR" "$INSTALL_DIR"

# --- download and extract bot (if applicable) ---
log "Downloading bot package..."
BOT_ZIP_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/bot.zip"
BOT_ZIP="/tmp/bot.zip"
if wget -q -O "$BOT_ZIP" "$BOT_ZIP_URL"; then
    unzip -o "$BOT_ZIP" -d "$TMPDIR/bot" >/dev/null 2>&1 || true
    if [[ -d "$TMPDIR/bot" ]]; then
        # move bot files into install dir (create subdir 'bot' to avoid clobbering)
        mkdir -p "$INSTALL_DIR/bot"
        cp -r "$TMPDIR/bot/"* "$INSTALL_DIR/bot/" 2>/dev/null || true
        log "Bot files installed to $INSTALL_DIR/bot"
    else
        log "No bot content found in $BOT_ZIP"
    fi
    rm -f "$BOT_ZIP"
else
    log "Failed to download bot.zip (continuing if not required)"
fi

# --- download and extract kyt ---
log "Downloading kyt package..."
KYT_ZIP_URL="https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/kyt.zip"
KYT_ZIP="/tmp/kyt.zip"
if wget -q -O "$KYT_ZIP" "$KYT_ZIP_URL"; then
    unzip -o "$KYT_ZIP" -d "$TMPDIR/kyt" >/dev/null 2>&1 || true
    if [[ -d "$TMPDIR/kyt" ]]; then
        cp -r "$TMPDIR/kyt/"* "$INSTALL_DIR/" || true
        log "Kyt files installed to $INSTALL_DIR"
    else
        err "No kyt content found in archive."
        rm -f "$KYT_ZIP"
        exit 1
    fi
    rm -f "$KYT_ZIP"
else
    err "Failed to download kyt.zip"
    exit 1
fi

# --- set permissions ---
chmod -R 755 "$INSTALL_DIR" || true

# --- install python requirements if present ---
REQ_FILE="$INSTALL_DIR/requirements.txt"
if [[ -f "$REQ_FILE" ]]; then
    log "Installing Python requirements..."
    pip3 install -r "$REQ_FILE" || {
        err "pip install failed"
        # continue; service may still work without optional deps
    }
fi

# --- prompt user for Bot Token and Admin ID ---
echo ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "          ADD BOT PANEL"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Tutorial: Create Bot and get Bot Token from @BotFather"
log "Get your Telegram ID from @MissRose_bot (use /info)"
echo ""
read -r -p "[*] Input your Bot Token: " BOT_TOKEN
read -r -p "[*] Input your Admin Telegram ID: " ADMIN_ID

# --- write var file ---
VAR_FILE="$INSTALL_DIR/var.txt"
cat > "$VAR_FILE" <<EOF
BOT_TOKEN="${BOT_TOKEN}"
ADMIN_ID="${ADMIN_ID}"
DOMAIN="${DOMAIN_VAL}"
PUB="${PUB_VAL}"
HOST="${NS_VAL}"
EOF
chmod 600 "$VAR_FILE"
log "Configuration written to $VAR_FILE"

# --- create systemd service ---
SERVICE_FILE="/etc/systemd/system/kyt.service"
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
WorkingDirectory=/usr/bin/kyt
ExecStart=/usr/bin/python3 -m kyt
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

log "Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable kyt.service
systemctl restart kyt.service || {
    err "Failed to start kyt.service; check 'journalctl -u kyt.service' for details"
}

# --- cleanup ---
rm -rf "$TMPDIR"
# optional: remove installer script if running from same file
# rm -f "$0" || true

# --- summary output ---
echo ""
log "Done"
echo "Your Bot Data:"
echo "Token Bot : $BOT_TOKEN"
echo "Admin ID  : $ADMIN_ID"
echo "Domain    : ${DOMAIN_VAL:-N/A}"
echo "Pub       : ${PUB_VAL:-N/A}"
echo "Host      : ${NS_VAL:-N/A}"
echo ""
log "Setting done. Installations complete. Send /menu to your bot (if supported)."
```// filepath: c:\Users\LAU-SPIDEY\Downloads\Lau_Op-main\kyt.sh
#!/bin/bash
set -euo pipefail

# kyt installer - fixed and robust
# Preserves original intent: download bot + kyt, install, write vars, create systemd service

# --- helpers ---
log() { echo -e "\033[36m$*\033[0m"; }
err() { echo -e "\033[31m$*\033[0m" >&2; }

# --- read system values with safe fallbacks ---
DNS_FILE="/etc/xray/dns"
SLOWDNS_PUB="/etc/slowdns/server.pub"
DOMAIN_FILE="/etc/xray/domain"
NS_FILE="/etc/xray/ns"

DNS_VAL=""
PUB_VAL=""
DOMAIN_VAL=""
NS_VAL=""

if [[ -r "$DNS_FILE" ]]; then
    DNS_VAL="$(tr -d '\n' < "$DNS_FILE")"
fi

if [[ -r "$SLOWDNS_PUB" ]]; then
    PUB_VAL="$(tr -d '\n' < "$SLOWDNS_PUB")"
fi

if [[ -r "$DOMAIN_FILE" ]]; then
    DOMAIN_VAL="$(tr -d '\n' < "$DOMAIN_FILE")"
fi

if [[ -r "$NS_FILE" ]]; then
    NS_VAL="$(tr -d '\n' < "$NS_FILE")"
fi

# fallback for NS if not set
if [[ -z "$NS_VAL" ]]; then
    NS_VAL="${DNS_VAL:-$(hostname -f 2>/dev/null || hostname)}"
fi

# --- install packages ---
log "Updating package lists and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt upgrade -y
apt install -y python3 python3-pip unzip wget git || {
    err "Failed to install required packages"
    exit 1
}

# --- prepare directories ---
INSTALL_DIR="/usr/bin/kyt"
TMPDIR="/tmp/kyt_install_$$"
mkdir -p "$TMPDIR" "$INSTALL_DIR"

# --- download and extract bot (if applicable) ---
log "Downloading bot package..."
BOT_ZIP_URL="https://raw.githubusercontent.com/Amchapeey/strategic/main/ubuntu/bot.zip"
BOT_ZIP="/tmp/bot.zip"
if wget -q -O "$BOT_ZIP" "$BOT_ZIP_URL"; then
    unzip -o "$BOT_ZIP" -d "$TMPDIR/bot" >/dev/null 2>&1 || true
    if [[ -d "$TMPDIR/bot" ]]; then
        # move bot files into install dir (create subdir 'bot' to avoid clobbering)
        mkdir -p "$INSTALL_DIR/bot"
        cp -r "$TMPDIR/bot/"* "$INSTALL_DIR/bot/" 2>/dev/null || true
        log "Bot files installed to $INSTALL_DIR/bot"
    else
        log "No bot content found in $BOT_ZIP"
    fi
    rm -f "$BOT_ZIP"
else
    log "Failed to download bot.zip (continuing if not required)"
fi

# --- download and extract kyt ---
log "Downloading kyt package..."
KYT_ZIP_URL="https://raw.githubusercontent.com/Amchapeey/strategic/main/ubuntu/kyt.zip"
KYT_ZIP="/tmp/kyt.zip"
if wget -q -O "$KYT_ZIP" "$KYT_ZIP_URL"; then
    unzip -o "$KYT_ZIP" -d "$TMPDIR/kyt" >/dev/null 2>&1 || true
    if [[ -d "$TMPDIR/kyt" ]]; then
        cp -r "$TMPDIR/kyt/"* "$INSTALL_DIR/" || true
        log "Kyt files installed to $INSTALL_DIR"
    else
        err "No kyt content found in archive."
        rm -f "$KYT_ZIP"
        exit 1
    fi
    rm -f "$KYT_ZIP"
else
    err "Failed to download kyt.zip"
    exit 1
fi

# --- set permissions ---
chmod -R 755 "$INSTALL_DIR" || true

# --- install python requirements if present ---
REQ_FILE="$INSTALL_DIR/requirements.txt"
if [[ -f "$REQ_FILE" ]]; then
    log "Installing Python requirements..."
    pip3 install -r "$REQ_FILE" || {
        err "pip install failed"
        # continue; service may still work without optional deps
    }
fi

# --- prompt user for Bot Token and Admin ID ---
echo ""
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "          ADD BOT PANEL"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Tutorial: Create Bot and get Bot Token from @BotFather"
log "Get your Telegram ID from @MissRose_bot (use /info)"
echo ""
read -r -p "[*] Input your Bot Token: " BOT_TOKEN
read -r -p "[*] Input your Admin Telegram ID: " ADMIN_ID

# --- write var file ---
VAR_FILE="$INSTALL_DIR/var.txt"
cat > "$VAR_FILE" <<EOF
BOT_TOKEN="${BOT_TOKEN}"
ADMIN_ID="${ADMIN_ID}"
DOMAIN="${DOMAIN_VAL}"
PUB="${PUB_VAL}"
HOST="${NS_VAL}"
EOF
chmod 600 "$VAR_FILE"
log "Configuration written to $VAR_FILE"

# --- create systemd service ---
SERVICE_FILE="/etc/systemd/system/kyt.service"
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
WorkingDirectory=/usr/bin/kyt
ExecStart=/usr/bin/python3 -m kyt
Restart=always
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

log "Reloading systemd and enabling service..."
systemctl daemon-reload
systemctl enable kyt.service
systemctl restart kyt.service || {
    err "Failed to start kyt.service; check 'journalctl -u kyt.service' for details"
}

# --- cleanup ---
rm -rf "$TMPDIR"
# optional: remove installer script if running from same file
# rm -f "$0" || true

# --- summary output ---
echo ""
log "Done"
echo "Your Bot Data:"
echo "Token Bot : $BOT_TOKEN"
echo "Admin ID  : $ADMIN_ID"
echo "Domain    : ${DOMAIN_VAL:-N/A}"
echo "Pub       : ${PUB_VAL:-N/A}"
echo "Host      : ${NS_VAL:-N/A}"
echo ""
log "Setting done. Installations complete. Send /menu to your bot (if supported)."