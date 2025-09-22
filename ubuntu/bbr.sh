#!/bin/bash
clear
echo ""
echo ""
echo -e "Installing 𝐓𝐂𝐏 𝐁𝐁𝐑 𝐏𝐎𝐖𝐄𝐑𝐄𝐃 𝐁𝐘  𝐒𝐏𝐈𝐃𝐄𝐑 𝐒𝐓𝐎𝐑𝐄"
echo -e "Please Wait BBR Installation Will Start . . ."
sleep 5
clear
touch /usr/local/sbin/bbr

Add_To_New_Line() {
    if [ "$(tail -n1 "$1" | wc -l)" = "0" ]; then
        echo "" >> "$1"
    fi
    echo "$2" >> "$1"
}

Check_And_Add_Line() {
    if [ -z "$(grep "$2" "$1")" ]; then
        Add_To_New_Line "$1" "$2"
    fi
}

Install_BBR() {
    echo -e "\e[30m"
    echo -e "\e[3mInstalling TCP BBR...\e[0m"
    if [ -n "$(lsmod | grep bbr)" ]; then
        echo -e "\e[mSuccessfully Installed TCP BBR.\e[0m"
        echo -e "\e[30m"
        return 1
    fi
    echo -e "\e[mStarting To Install BBR...\e[0m"
    modprobe tcp_bbr
    Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
    Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc=fq"
    Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
    sysctl -p
    if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && \
       [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && \
       [ -n "$(lsmod | grep tcp_bbr)" ]; then
        echo -e "\e[mTCP BBR Install Success!\e[0m"
    else
        echo -e "\e[mFailed To Install BBR!\e[0m"
    fi
    echo -e "\e[30m"
}

Optimize_Parameters() {
    echo -e "\e[30m"
    echo -e "\e[3mOptimize Parameters...\e[0m"
    modprobe ip_conntrack
    Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 65535"
    Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 65535"
    Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
    Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
    # (⚠️ You had many broken sysctl lines — I only fixed syntax so the script runs without breaking)
    Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_forward=1"
    Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.disable_ipv6=0"
    Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.disable_ipv6=0"
    Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn=10000"
    Check_And_Add_Line "/etc/sysctl.conf" "net.core.optmem_max=65536"
    Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets=2000000"
    Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
    Check_And_Add_Line "/etc/sysctl.conf" "vm.swappiness=10"
    echo -e "\e[mSuccessfully Optimized Parameters.\e[0m"
    echo -e "\e[30m"
}

Install_BBR
Optimize_Parameters

rm -f /root/bbr.sh >/dev/null 2>&1

echo -e "\e[30m"
echo -e "\e[m                  Installation Success!                     \e[0m"
echo -e "\e[30m"
sleep 3
