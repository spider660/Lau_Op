#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
user2=$(grep -wE "^#trg $user" "/etc/xray/config.json" | cut -d ' ' -f 2 | sort | uniq)
exp=$(grep -wE "^#trg $user" "/etc/xray/config.json" | cut -d ' ' -f 3 | sort | uniq)

if [ $user2 = $user ]; then
        cd
        sed -i "/^#tr $user $exp/,/^},{/d" /etc/xray/config.json
        sed -i "/^#trg $user $exp/,/^},{/d" /etc/xray/config.json
        rm -rf /home/vps/public_html/trojan-$user.txt
        rm -rf /etc/trojan/${user}IP
        rm -rf /etc/trojan/${user}login
        rm -rf /etc/cron.d/trialtrojan$user
        systemctl restart xray
        fi