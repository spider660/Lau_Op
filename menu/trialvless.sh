#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Pastikan variabel user sudah didefinisikan
if [ -z "$user" ]; then
    echo "Error: Variabel 'user' belum didefinisikan."
    exit 1
fi

user2=$(grep -wE "^#vl $user" "/etc/xray/config.json" | cut -d ' ' -f 2 | sort | uniq)
exp=$(grep -wE "^#vl $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)

if [[ "$user2" == "$user" ]]; then
    cd || exit 1  # Pastikan cd berhasil
    sed -i "/^#vl $user $exp/,/^},{/d" /etc/xray/config.json
    sed -i "/^#vlg $user $exp/,/^},{/d" /etc/xray/config.json
    rm -rf "/home/vps/public_html/vless-$user.txt"
    rm -rf "/etc/vless/${user}IP"
    rm -rf "/etc/vless/${user}login"
    rm -rf "/etc/cron.d/trialvless$user"
    systemctl restart xray
else
    echo "User  '$user' tidak ditemukan dalam konfigurasi."
fi