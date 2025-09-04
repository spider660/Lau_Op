#!/bin/bash

# Load variables
NS=$(cat /etc/xray/dns)
PUB=$(cat /etc/slowdns/server.pub)
domain=$(cat /etc/xray/domain)

# Colors
grenbo="\e[36m"
NC="\e[0m"

# Update and install dependencies
apt update && apt upgrade -y
apt install -y python3 python3-pip git unzip wget

# Install bot files
cd /usr/bin || exit
wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/bot.zip
unzip -o bot.zip
mv bot/* /usr/bin/
chmod +x /usr/bin/*
rm -rf bot.zip

# Install kyt files
wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/kyt.zip
unzip -o kyt.zip
pip3 install -r kyt/requirements.txt

# Display setup instructions
echo -e "${grenbo}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "          ADD BOT PANEL"
echo -e "${grenbo}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${grenbo}Tutorial: Create Bot and get Telegram ID${NC}"
echo -e "${grenbo}[*] Create Bot and Token Bot: @BotFather${NC}"
echo -e "${grenbo}[*] Info ID Telegram: @MissRose_bot, command /info${NC}"
echo -e "${grenbo}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Get user input
read -e -p "[*] Input your Bot Token: " bottoken
read -e -p "[*] Input Your Telegram ID: " admin

# Save variables
cat > /usr/bin/kyt/var.txt << EOF
BOT_TOKEN='$bottoken'
ADMIN='$admin'
DOMAIN='$domain'
PUB='$PUB'
HOST='$NS'
EOF

# Create systemd service
cat > /etc/systemd/system/kyt.service << EOF
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
WorkingDirectory=/usr/bin
ExecStart=/usr/bin/python3 -m kyt
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start and enable service
systemctl daemon-reload
systemctl start kyt
systemctl enable kyt
systemctl restart kyt

# Cleanup
cd /root || exit
rm -rf kyt.sh

# Display info
echo -e "Done"
echo -e "Your Bot Data:"
echo -e "Token Bot: $bottoken"
echo -e "Admin: $admin"
echo -e "Domain: $domain"
echo -e "Pub: $PUB"
echo -e "Host: $NS"
echo -e "Setting done. Installations complete, type /menu on your bot"
