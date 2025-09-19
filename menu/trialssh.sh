#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if [ $user2 = $user ]; then
        cd
        getent passwd $user
        userdel -f $user
        exp=$(grep -wE "^### $user" "/etc/xray/ssh" | cut -d ' ' -f 3 | sort | uniq)
        pass=$(grep -wE "^### $user" "/etc/xray/ssh" | cut -d ' ' -f 4 | sort | uniq)
        sed -i "s/### $user $exp $pass//g" /etc/xray/ssh 
        rm -rf /home/vps/public_html/ssh-$user.txt
        rm -rf /etc/xray/sshx/${user}IP
        rm -rf /etc/xray/sshx/${user}login
        rm -rf /etc/cron.d/trialssh$user
        systemctl restart sshd
fi