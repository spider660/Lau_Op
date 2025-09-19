#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

clear
# install Ruby & Yum
apt-get install ruby -y
# install lolcat
wget https://github.com/busyloop/lolcat/archive/master.zip
unzip master.zip
rm -f master.zip
cd lolcat-master/bin
gem install lolcat
# install figlet
apt-get install figlet
# Install figlet ascii
sudo apt-get install figlet
git clone https://github.com/busyloop/lolcat
cd lolcat/bin && gem install lolcat
cd /usr/share
git clone https://github.com/xero/figlet-fonts
mv figlet-fonts/* figlet && rm –rf figlet-fonts

cd
rm -f lolcat.sh
