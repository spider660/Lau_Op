# (original content with only syntax fixes)
echo "re'\\e[m'"
echo "greee[32m'\'"
echo "purpl\e[0'\'"
echo "orang\e[0'\'"
echo "N\e[0m'\'"
clear
echo ""
echo ""
echo -e "Installing 𝐓𝐂𝐏 ��𝐁�� 𝐏𝐎𝐖𝐄𝐑𝐄𝐃 𝐁𝐘 𝐒𝐏𝐈𝐃𝐄𝐑𝐖𝐄𝐁𝐗 𝐒𝐓𝐎𝐑𝐄"
echo -e "Please Wait BBR Installation Will Starting . . ."
sleep 5
clear
touch /usr/local/sbin/bbr

Add_To_New_Line(){
  if [ "$(tail -n1 "$1" | wc -l)" -eq 0 ]; then
    echo "" >> "$1"
  fi
  echo "$2" >> "$1"
}

Check_And_Add_Line(){
  if [ -z "$(cat "$1" | grep "$2")" ]; then
    Add_To_New_Line "$1" "$2"
  fi
}

Install_BBR(){
  echo -e "\e[30m"
  echo -e "\e[3mInstalling TCP BBR...\e[0m"
  if [ -n "$(lsmod | grep bbr)" ]; then
    echo -e "\e[mSuccesfully Installed TCP BBR.\e[0m"
    echo -e "\e[30m"
    return 1
  fi
  echo -e "\e[mStarting To Install BBR...\e[0m"
  modprobe tcp_bbr
  Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
  Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc fq"
  Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control r"
  sysctl -p
  if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && \
     [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && \
     [ -n "$(lsmod | grep "tcp_bbr")" ]; then
    echo -e "\e[mTCP BBR Install Success!\e[0m"
  else
    echo -e "\e[mFailed To Install BBR!\e[0m"
  fi
  echo -e "\e[30m"
}

Optimize_Parameters(){
  echo -e "\e[30m"
  echo -e "\e[3mOptimize Parameters...\e[0m"
  modprobe ip_conntrack
  Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 65535"
  Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 65535"
  Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
  Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.route_localne1"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_forward 1"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.forwarding "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.forwarding "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.forwarding "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.forwarding "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.forwarding 1"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.disable_ipv60"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.disable_ipv60"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.lo.disable_ipv6"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_ra 2"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_ra 2"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget50000"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_budget_usecs 00"
  Check_And_Add_Line "/etc/sysctl.conf" "#fs.file-max 200"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max7108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max7108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_default7108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_default7108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.optmem_max 65536"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn10000"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_all"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_echo_ignore_broadcasts "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.icmp_ignore_bogus_error_responses1"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.accept_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.accept_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.secure_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.secure_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.send_redirects "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.send_redirects "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.rp_filter 0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.rp_filter 0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time 1200"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_intvl "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_probes"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_synack_retries 2"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies 0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rfc1337 "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_timestamps 1"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range 24 65535"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets 2000000"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem096 87380 67108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem096 65536 67108864"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_rmem_min192"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.udp_wmem_min192"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_ignore "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_ignore "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.all.arp_announce2"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.conf.default.arp_announce2"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_autocorking "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_slow_start_after_idle0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog 000"
  Check_And_Add_Line "/etc/sysctl.conf" "net.core.default_qdiscfq"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control bbr"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_notsent_lowat16384"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_no_metrics_save "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn "
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_ecn_fallback"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_frto"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.all.accept_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.conf.default.accept_redirects0"
  Check_And_Add_Line "/etc/sysctl.conf" "vm.swappiness"
  Check_And_Add_Line "/etc/sysctl.conf" "vm.overcommit_memory "
  Check_And_Add_Line "/etc/sysctl.conf" "#vm.nr_hugepage1280"
  Check_And_Add_Line "/etc/sysctl.conf" "kernel.pid_ma000"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh32"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh26"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.neigh.default.gc_thresh18"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh32"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh26"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv6.neigh.default.gc_thresh18"
  Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog 2144"
  Check_And_Add_Line "/etc/sysctl.conf" "net.netfilter.nf_conntrack_max262144"
  Check_And_Add_Line "/etc/sysctl.conf" "net.nf_conntrack_max 2144"
  Check_And_Add_Line "/etc/systemd/system.conf" "DefaultTimeoutStopSec"
  Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitCORinfinity"
  Check_And_Add_Line "/etc/systemd/system.conf" "DefaultLimitNOFIL535"
  echo -e "\e[mSuccesfully Optimize Parameters.\e[0m"
  echo -e "\e[30m"
}

Install_BBR
Optimize_Parameters
rm -f /root/bbr.sh >/dev/null 2>&1
echo -e '\e[30m'
echo -e '\e[m                  Installation Success!                     \e[0m'
echo -e '\e[30m'
sleep 3
