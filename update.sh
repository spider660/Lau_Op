#!/bin/bash

# Get date from server
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
bijite=$(date +"%Y-%m-%d" -d "$dateFromServer")

# Color function
red() { echo -e "\033[3${*}m\033[0m"; }

# Loading bar function
fun_bar() {
    CMD[0]="$1"
    CMD[1]="$2"
    (
        [[ -e $HOME/fim ]] && rm $HOME/fim
        ${CMD[0]} -y >/dev/null 2>&1
        ${CMD[1]} -y >/dev/null 2>&1
        touch $HOME/fim
    ) >/dev/null 2>&1 &

    tput civis
    echo -ne "  \033[3mPlease Wait Loading \033[1m[\033[0m"
    while true; do
        for ((i=0; i<1; i++)); do
            echo -ne "#"
            sleep 0.1
        done
        [[ -e $HOME/fim ]] && rm $HOME/fim && break
        echo -ne "]"
        sleep 1
        tput cuu1
        tput dl1
        echo -ne "  \033[3mPlease Wait Loading \033[1m[\033[0m"
    done
    echo -e "]\033[7m -\033[2m OK !\033[m"
    tput cnorm
}

# Update menu function
res1() {
    wget -q https://raw.githubusercontent.com/spider660/Lau_Op/main/ubuntu/menu.zip
    unzip -o menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin/
    rm -rf menu menu.zip update.sh
}

# Apply netfilter-persistent if installed
command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent

clear
echo -e "\033[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1m      UPDATED SCRIPT POWERED BY SPIDER      \e[0m"
echo -e "\033[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "  \033[mUpdate script service\033[m"
fun_bar 'res1'
echo -e "\033[36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "Press [ Enter ] to return to menu"
menu
