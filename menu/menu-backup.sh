#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Mendefinisikan warna untuk pesan
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BIRU='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
CYAN_BG='\033[46;1;97m'   # Latar belakang cyan cerah dengan teks putih
LIGHT='\033[0;37m'
PINK='\033[0;35m'
ORANGE='\033[38;5;208m'
PINK_BG='\033[45;1;97m'
BIRU_BG='\033[44;1;97m'
RED_BG='\033[41;1;97m'   # Latar belakang pink cerah dengan teks putih
NC='\033[0m'
INDIGO='\033[38;5;54m'
TEAL='\033[38;5;30m'
WHITE='\033[1;37m'
clear

#Banner Ssh
  echo -e " ${CYAN}======================================${NC}"
  echo -e " ${BIRU_BG}               BY SFTP               ${NC}"
  echo -e " ${CYAN}======================================${NC}"
  echo -e "  1.) Manual Backup VPS Data "  
  echo -e "  2.) Restore VPS Data Via SFTP   " 
  echo -e " ${CYAN}======================================${NC}"
  echo -e "  x.) Back to Menu       "
  echo -e " ${CYAN}======================================${NC}"
  echo -e " "

read -p "  ➣ Your Choice: " NB
case $NB in
      1) echo -e "${TEAL} ➣ Service Backup selected ${NC}"  
         manual-backup
         ;;
      2) echo -e "${TEAL} ➣ Service Restore selected ${NC}"  
         manual-restore
         ;;
      x) clear ; menu ;;
      *) phreakers-fitur ;;
esac
