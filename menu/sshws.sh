
#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Request : Debian 9+/Ubuntu 18.04+/20+
# Develovers » ŞƤƗĐ€Ř
# Email      » laubuoy@gmail.com
# telegram   » https://t.me/spid_3r
# whatsapp   » wa.me/+254112011036
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
clear

# =============================================
#           [ Konfigurasi Warna ]
# =============================================
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export NC='\033[0m'

# =============================================
#          [ Fungsi Pengecekan IP ]
check_ip_and_get_info() {
    local ip=$1
    while IFS= read -r line; do
        # Hapus karakter khusus dan spasi berlebih
        line=$(echo "$line" | tr -d '\r' | sed 's/[^[:print:]]//g' | xargs)
        
        # Split baris menjadi array
        read -ra fields <<< "$line"
        
        
        # Kolom 4 = IP Address (index 3)
        if [[ "${fields[3]}" == "$ip" ]]; then
            client_name="${fields[1]}"  # Kolom 2
            exp_date="${fields[2]}"     # Kolom 3
            
            # Bersihkan tanggal dari karakter khusus
            exp_date=$(echo "$exp_date" | sed 's/[^0-9-]//g' | xargs)
            
            return 0
        fi
    done <<< "$permission_file"
    return 1
}

# =============================================
#          [ Main Script ]
# =============================================

# Ambil data dari GitHub dengan timeout
permission_file=$(curl -s --connect-timeout 10 https://raw.githubusercontent.com/spider660/key/refs/heads/main/net)

# Validasi file permission
if [ -z "$permission_file" ]; then
    echo -e "${RED}❌ Gagal mengambil data lisensi!${NC}"
    exit 1
fi

# Ambil IP VPS dengan metode alternatif
IP_VPS=$(curl -s ipv4.icanhazip.com)

# =============================================
#          [ Pengecekan IP ]
# =============================================
echo -e "${GREEN}⌛ Checking license...${NC}"
if check_ip_and_get_info "$IP_VPS"; then
    
    # Validasi format tanggal ISO 8601
    if ! [[ "$exp_date" =~ ^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$ ]]; then
        echo -e "${RED}❌ Invalid date format: '$exp_date' (must be YYYY-MM-DD)${NC}"
        exit 1
    fi

    # Validasi tanggal menggunakan date
    if ! date -d "$exp_date" "+%s" &>/dev/null; then
        echo -e "${RED}❌ Date is not valid according to the calendar: $exp_date${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ IP not registered!${NC}"
    echo -e "➥ Contact admin ${CYAN}「 ✦ @spid_3r ✦ 」${NC}"
    exit 1
fi

# =============================================
#          [ Hitung Hari Tersisa ]
# =============================================
current_epoch=$(date +%s)
exp_epoch=$(date -d "$exp_date" +%s)

if (( exp_epoch < current_epoch )); then
    echo -e "${RED}❌ Masa aktif telah habis!${NC}"
    exit 1
fi

days_remaining=$(( (exp_epoch - current_epoch) / 86400 ))
###########- COLOR CODE -##############
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export NC='\033[0m' # No Color
COLOR1='\033[0;32m'
WH='\033[1;37m'
#######################################

###########- SYSTEM INFO -#############
# Server Information
date_server=$(date -u +"%Y-%m-%d")
wkt_server=$(timedatectl | grep "Time zone" | awk '{print $3}' | tr -d '()')

# RAM Information
tram=$(free -h | awk '/Mem:/ {print $2}')
uram=$(free -h | awk '/Mem:/ {print $3}')

# Network Information
ipsaya=$(curl -s4 ifconfig.me)
ipvps=$(curl -s4 ifconfig.me)
isp=$(curl -s ipinfo.io/org | cut -d ' ' -f 2-10)
city=$(curl -s ipinfo.io/city)

#######################################

colornow=$(cat /etc/phreakers/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m"
COLOR1="$(cat /etc/phreakers/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/phreakers/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"
WH='\033[1;37m'
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
author=$(cat /etc/profil)
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
domain=`cat /etc/xray/domain`
CHATID2=$(cat /etc/perlogin/id)
KEY2=$(cat /etc/perlogin/token)
URL2="https://api.telegram.org/bot$KEY2/sendMessage"
cd
if [ ! -e /etc/xray/sshx/akun ]; then
mkdir -p /etc/xray/sshx/akun
fi
function usernew() {
    clear
    domen=$(cat /etc/xray/domain)
    sldomain=$(cat /etc/xray/dns)
    slkey=$(cat /etc/slowdns/server.pub)
    TIMES="10"
    CHATID=$(cat /etc/per/id)
    KEY=$(cat /etc/per/token)
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    ISP=$(cat /etc/xray/isp)
    CITY=$(cat /etc/xray/city)
    author=$(cat /etc/profil)
    
    clear
    echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
    echo -e "$COLOR1│${NC}${COLBG1}               ${WH}• SSH PANEL MENU •                ${NC}$COLOR1│ $NC"
    echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
    
    while true; do
        read -p "Username : " Login
        if [[ ! "$Login" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
            echo -e "Username contains invalid characters! Please use only letters, numbers, dots, underscores, or hyphens."
            continue
        fi
        
        # Cek apakah username ada di sistem atau di file /etc/xray/ssh
        CLIENT_EXISTS_IN_SYSTEM=$(id "$Login" &>/dev/null; echo $?)
        CLIENT_EXISTS_IN_FILE=$(grep -w "^### $Login " /etc/xray/ssh | wc -l)
        
        if [ "$CLIENT_EXISTS_IN_SYSTEM" -eq 0 ] || [ "$CLIENT_EXISTS_IN_FILE" -ge 1 ]; then
            # Jika user ada di sistem, cek kedaluwarsa
            if [ "$CLIENT_EXISTS_IN_SYSTEM" -eq 0 ]; then
                exp_date=$(chage -l "$Login" | grep "Account expires" | awk -F': ' '{print $2}')
                exp_epoch=$(date -d "$exp_date" +%s 2>/dev/null)
                now_epoch=$(date +%s)
                
                if [ "$exp_epoch" -lt "$now_epoch" ]; then
                    # Hapus user kedaluwarsa
                    userdel -r "$Login" >/dev/null 2>&1
                    sed -i "/^### $Login /d" /etc/xray/ssh
                    rm -f "/etc/xray/sshx/${Login}IP" "/home/vps/public_html/ssh-$Login.txt"
                    echo -e "Akun kedaluwarsa $Login telah dihapus. Silahkan buat baru."
                    break
                else
                    echo -e "Username $Login masih aktif hingga $exp_date!"
                    continue
                fi
            else
                # Hapus entri di file jika user tidak ada di sistem
                sed -i "/^### $Login /d" /etc/xray/ssh
                rm -f "/etc/xray/sshx/${Login}IP" "/home/vps/public_html/ssh-$Login.txt"
                break
            fi
        else
            break
        fi
    done
    
    # Lanjutkan proses pembuatan akun...
    read -p "Password : " Pass
    until [[ $masaaktif =~ ^[0-9]+$ ]]; do
        read -p "Expired (hari): " masaaktif
    done
    until [[ $iplim =~ ^[0-9]+$ ]]; do
        read -p "Limit User (IP): " iplim
    done
    
    # ... (sisa kode tetap sama)

if [ ! -e /etc/xray/sshx ]; then
mkdir -p /etc/xray/sshx
fi
if [ -z ${iplim} ]; then
iplim="0"
fi
echo "${iplim}" >/etc/xray/sshx/${Login}IP
IP=$(curl -sS ifconfig.me);
if [[ -e /etc/cloudfront ]]; then
cloudfront=$(cat /etc/cloudfront)
else
cloudfront="-"
fi
sleep 1
clear
expi=`date -d "$masaaktif days" +"%Y-%m-%d"`
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e "### $Login $expi $Pass" >> /etc/xray/ssh
cat > /home/vps/public_html/ssh-$Login.txt <<-END
_______________________________
Format SSH OVPN Account
_______________________________
Username         : $Login
Password         : $Pass
Expired          : $exp
_______________________________
Host             : $domen
ISP              : $ISP
CITY             : $CITY
Login Limit      : ${iplim} IP
Port OpenSSH     : 22
Port Dropbear    : 143, 109
Port SSH WS      : 80, 8080
Port SSH SSL WS  : 443
Port SSL/TLS     : 8443, 8880
Port OVPN WS SSL : 2086
Port OVPN SSL    : 990
Port OVPN TCP    : 1194
Port OVPN UDP    : 2200,
BadVPN UDP       : 7100, 7300, 7300
_______________________________
Host Slowdns    : $sldomain
Port Slowdns     : 80, 443, 53
Pub Key          : $slkey
_______________________________
SSH UDP VIRAL : $domen:1-65535@$Login:$Pass
_______________________________
HTTP COSTOMM : $domen:80@$Login:$Pass
_______________________________
Payload WS/WSS   :
GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]
_______________________________
OpenVPN SSL      : http://$domen:89/ssl.ovpn
OpenVPN TCP      : http://$domen:89/tcp.ovpn
OpenVPN UDP      : http://$domen:89/udp.ovpn
_______________________________
END
if [[ -e /etc/cloudfront ]]; then
TEXT="
◇━━━━━━━━━━━━━━━━━◇
SSH Premium Account
◇━━━━━━━━━━━━━━━━━◇
Username        :  <code>$Login</code>
Password        :  <code>$Pass</code>
Expired On       :  $exp
◇━━━━━━━━━━━━━━━━━◇
ISP              :  $ISP
CITY             :  $CITY
Host             :  <code>$domen</code>
Login Limit      :  ${iplim} IP
Port OpenSSH    :  22
Port Dropbear    :  109, 143
Port SSH WS     :  80, 8080
Port SSH SSL WS :  443
Port SSL/TLS     :  8443,8880
Port OVPN WS SSL :  2086
Port OVPN SSL    :  990
Port OVPN TCP    :  1194
Port OVPN UDP    :  2200
Proxy Squid        :  3128
BadVPN UDP       :  7100, 7300, 7300
◇━━━━━━━━━━━━━━━━━◇
SSH UDP VIRAL : <code>$domen:1-65535@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
HTTP CUSTOM WS : <code>$domen:80@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
Host Slowdns    :  <code>$sldomain</code>
Port Slowdns     :  80, 443, 53
Pub Key          :  <code> $slkey</code>
◇━━━━━━━━━━━━━━━━━◇
Payload WS/WSS   :
<code>GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]</code>
◇━━━━━━━━━━━━━━━━━◇
OpenVPN SSL      :  http://$domen:89/ssl.ovpn
OpenVPN TCP      :  http://$domen:89/tcp.ovpn
OpenVPN UDP      :  http://$domen:89/udp.ovpn
◇━━━━━━━━━━━━━━━━━◇
Save Link Account: http://$domen:89/ssh-$Login.txt
◇━━━━━━━━━━━━━━━━━◇
 
"
else
TEXT="
◇━━━━━━━━━━━━━━━━━◇
SSH Premium Account
◇━━━━━━━━━━━━━━━━━◇
Username        :  <code>$Login</code>
Password        :  <code>$Pass</code>
Expired On       :  $exp
◇━━━━━━━━━━━━━━━━━◇
ISP              :  $ISP
CITY             :  $CITY
Host             :  <code>$domen</code>
Login Limit      :  ${iplim} IP
Port OpenSSH    :  22
Port Dropbear    :  109, 143
Port SSH WS     :  80, 8080
Port SSH SSL WS :  443
Port SSL/TLS     :  8443,8880
Port OVPN WS SSL :  2086
Port OVPN SSL    :  990
Port OVPN TCP    :  1194
Port OVPN UDP    :  2200
Proxy Squid        :  3128
BadVPN UDP       :  7100, 7300, 7300
◇━━━━━━━━━━━━━━━━━◇
SSH UDP VIRAL : <code>$domen:1-65535@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
HTTP CUSTOM WS : <code>$domen:80@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
Host Slowdns    :  <code>$sldomain</code>
Port Slowdns     :  80, 443, 53
Pub Key          :  <code> $slkey</code>
◇━━━━━━━━━━━━━━━━━◇
Payload WS/WSS   :
<code>GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]</code>
◇━━━━━━━━━━━━━━━━━◇
OpenVPN SSL      :  http://$domen:89/ssl.ovpn
OpenVPN TCP      :  http://$domen:89/tcp.ovpn
OpenVPN UDP      :  http://$domen:89/udp.ovpn
◇━━━━━━━━━━━━━━━━━◇
Save Link Account: http://$domen:89/ssh-$Login.txt
◇━━━━━━━━━━━━━━━━━◇
 
"
fi
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
user2=$(echo "$Login" | cut -c 1-3)
TIME2=$(date +'%Y-%m-%d %H:%M:%S')
clear
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC} ${WH}• SSH Premium Account  • " | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Username   ${COLOR1}: ${WH}$Login"  | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Password   ${COLOR1}: ${WH}$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Expired On ${COLOR1}: ${WH}$exp"  | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}ISP        ${COLOR1}: ${WH}$ISP" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}City       ${COLOR1}: ${WH}$CITY" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Host       ${COLOR1}: ${WH}$domen" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Login Limit${COLOR1}: ${WH}${iplim} IP" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OpenSSH    ${COLOR1}: ${WH}22" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Dropbear   ${COLOR1}: ${WH}109, 143" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSH-WS     ${COLOR1}: ${WH}80,8080" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSH-SSL-WS ${COLOR1}: ${WH}443" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSL/TLS    ${COLOR1}: ${WH}8443,8880" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Ovpn Ws    ${COLOR1}: ${WH}2086" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port TCP   ${COLOR1}: ${WH}1194" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port UDP   ${COLOR1}: ${WH}2200,1-65535" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port SSL   ${COLOR1}: ${WH}990" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN TCP   ${COLOR1}: ${WH}http://$domen:89/tcp.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN UDP   ${COLOR1}: ${WH}http://$domen:89/udp.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN SSL   ${COLOR1}: ${WH}http://$domen:89/ssl.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}UDPGW      ${COLOR1}: ${WH}7100-7300" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}PORT SLWDNS${COLOR1}: ${WH}80,443,53" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}NAMESERVER ${COLOR1}: ${WH}$sldomain" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}PUB KEY    ${COLOR1}: ${WH}$slkey" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}UDP VIRAL${COLOR1}: ${WH}$domen:1-65535@$Login:$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}HTTP CUSTOM${COLOR1}: ${WH}$domen:80@$Login:$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}Payload WS/WSS${COLOR1}: ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1${NC}${WH}GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}Save Link Acount    : " | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}http://$domen:89/ssh-$Login.txt${NC}$COLOR1 $NC" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}    ${WH}• SPIDER WEBX STORE •${NC}                 $COLOR1 $NC" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo "" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
function trial(){
clear
domen=`cat /etc/xray/domain`
sldomain=`cat /etc/xray/dns`
slkey=`cat /etc/slowdns/server.pub`
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
author=$(cat /etc/profil)
clear
IP=$(curl -sS ifconfig.me)
cd
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}            ${WH}• TRIAL SSH Account •                ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e ""
until [[ $timer =~ ^[0-9]+$ ]]; do
read -p "Expired (Minutes): " timer
done
Login=Trial-`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari=0
Pass=1
iplim=1
if [ ! -e /etc/xray/sshx ]; then
mkdir -p /etc/xray/sshx
fi
if [ -z ${iplim} ]; then
iplim="0"
fi
if [[ -e /etc/cloudfront ]]; then
cloudfront=$(cat /etc/cloudfront)
else
cloudfront="Kosong"
fi
echo "$iplim" > /etc/xray/sshx/${Login}IP
expi=`date -d "$hari days" +"%Y-%m-%d"`
useradd -e `date -d "$hari days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
echo -e "### $Login $expi $Pass" >> /etc/xray/ssh
tmux new-session -d -s $Login "trial ssh $Login $expi $Pass ${timer}"
cat > /home/vps/public_html/ssh-$Login.txt <<-END
_______________________________
Format SSH OVPN Account
_______________________________
Username         : $Login
Password         : $Pass
Expired          : $timer Minutes
_______________________________
Host             : $domen
ISP              : $ISP
CITY             : $CITY
Login Limit      : ${iplim} IP
Port OpenSSH     : 22
Port Dropbear    : 143, 109
Port SSH WS      : 80, 8080
Port SSH SSL WS  : 443
Port SSL/TLS     : 8443, 8880
Port OVPN WS SSL : 2086
Port OVPN SSL    : 990
Port OVPN TCP    : 1194
Port OVPN UDP    : 2200,
BadVPN UDP       : 7100, 7300, 7300
_______________________________
Host Slowdns    : $sldomain
Port Slowdns     : 80, 443, 53
Pub Key          : $slkey
_______________________________
SSH UDP VIRAL : $domen:1-65535@$Login:$Pass
_______________________________
HTTP CUSTOM : $domen:80@$Login:$Pass
_______________________________
Payload WS/WSS   :
GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]
_______________________________
OpenVPN SSL      : http://$domen:89/ssl.ovpn
OpenVPN TCP      : http://$domen:89/tcp.ovpn
OpenVPN UDP      : http://$domen:89/udp.ovpn
_______________________________
END
if [[ -e /etc/cloudfront ]]; then
TEXT="
◇━━━━━━━━━━━━━━━━━◇
Trial SSH Premium Account
◇━━━━━━━━━━━━━━━━━◇
Username        :  <code>$Login</code>
Password        :  <code>$Pass</code>
Expired On       :  $timer Minutes
◇━━━━━━━━━━━━━━━━━◇
ISP              :  $ISP
CITY             :  $CITY
Host             :  <code>$domen</code>
Login Limit      :  ${iplim} IP
Port OpenSSH    :  22
Port Dropbear    :  109, 143
Port SSH WS     :  80, 8080
Port SSH SSL WS :  443
Port SSL/TLS     :  8443,8880
Port OVPN WS SSL :  2086
Port OVPN SSL    :  990
Port OVPN TCP    :  1194
Port OVPN UDP    :  2200
Proxy Squid        :  3128
BadVPN UDP       :  7100, 7300, 7300
◇━━━━━━━━━━━━━━━━━◇
SSH UDP VIRAL : <code>$domen:1-65535@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
HTTP CUSTOM WS : <code>$domen:80@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
Host Slowdns    :  <code>$sldomain</code>
Port Slowdns     :  80, 443, 53
Pub Key          :  <code> $slkey</code>
◇━━━━━━━━━━━━━━━━━◇
Payload WS/WSS   :
<code>GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]</code>
◇━━━━━━━━━━━━━━━━━◇
OpenVPN SSL      :  http://$domen:89/ssl.ovpn
OpenVPN TCP      :  http://$domen:89/tcp.ovpn
OpenVPN UDP      :  http://$domen:89/udp.ovpn
◇━━━━━━━━━━━━━━━━━◇
Save Link Account: http://$domen:89/ssh-$Login.txt
◇━━━━━━━━━━━━━━━━━◇
 
"
else
TEXT="
◇━━━━━━━━━━━━━━━━━◇
Trial SSH Premium Account
◇━━━━━━━━━━━━━━━━━◇
Username        :  <code>$Login</code>
Password        :  <code>$Pass</code>
Expired On       :  $timer Minutes
◇━━━━━━━━━━━━━━━━━◇
ISP              :  $ISP
CITY             :  $CITY
Host             :  <code>$domen</code>
Login Limit      :  ${iplim} IP
Port OpenSSH    :  22
Port Dropbear    :  109, 143
Port SSH WS     :  80, 8080
Port SSH SSL WS :  443
Port SSL/TLS     :  8443,8880
Port OVPN WS SSL :  2086
Port OVPN SSL    :  990
Port OVPN TCP    :  1194
Port OVPN UDP    :  2200
Proxy Squid        :  3128
BadVPN UDP       :  7100, 7300, 7300
◇━━━━━━━━━━━━━━━━━◇
SSH UDP VIRAL : <code>$domen:1-65535@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
HTTP CUSTOM WS : <code>$domen:80@$Login:$Pass</code>
◇━━━━━━━━━━━━━━━━━◇
Host Slowdns    :  <code>$sldomain</code>
Port Slowdns     :  80, 443, 53
Pub Key          :  <code> $slkey</code>
◇━━━━━━━━━━━━━━━━━◇
Payload WS/WSS   :
<code>GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]</code>
◇━━━━━━━━━━━━━━━━━◇
OpenVPN SSL      :  http://$domen:89/ssl.ovpn
OpenVPN TCP      :  http://$domen:89/tcp.ovpn
OpenVPN UDP      :  http://$domen:89/udp.ovpn
◇━━━━━━━━━━━━━━━━━◇
Save Link Account: http://$domen:89/ssh-$Login.txt
◇━━━━━━━━━━━━━━━━━◇
 
"
fi
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
cat> /etc/cron.d/trialssh${Login} << EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/$timer * * * * root /usr/bin/trial ssh $Login $Pass $expi
EOF
clear
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC} ${WH}• Trial SSH Premium Account • " | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Username   ${COLOR1}: ${WH}$Login"  | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Password   ${COLOR1}: ${WH}$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Expired On ${COLOR1}: ${WH}$timer Minutes"  | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}ISP        ${COLOR1}: ${WH}$ISP" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}City       ${COLOR1}: ${WH}$CITY" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Host       ${COLOR1}: ${WH}$domen" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Login Limit${COLOR1}: ${WH}${iplim} IP" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OpenSSH    ${COLOR1}: ${WH}22" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Dropbear   ${COLOR1}: ${WH}109, 143" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSH-WS     ${COLOR1}: ${WH}80,8080" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSH-SSL-WS ${COLOR1}: ${WH}443" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}SSL/TLS    ${COLOR1}: ${WH}8443,8880" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Ovpn Ws    ${COLOR1}: ${WH}2086" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port TCP   ${COLOR1}: ${WH}1194" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port UDP   ${COLOR1}: ${WH}2200,1-65535" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}Port SSL   ${COLOR1}: ${WH}990" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN TCP   ${COLOR1}: ${WH}http://$domen:89/tcp.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN UDP   ${COLOR1}: ${WH}http://$domen:89/udp.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}OVPN SSL   ${COLOR1}: ${WH}http://$domen:89/ssl.ovpn" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}UDPGW      ${COLOR1}: ${WH}7100-7300" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}PORT SLWDNS${COLOR1}: ${WH}80,443,53" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}NAMESERVER ${COLOR1}: ${WH}$sldomain" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}PUB KEY    ${COLOR1}: ${WH}$slkey" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}UDP VIRAL${COLOR1}: ${WH}$domen:1-65535@$Login:$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 $NC  ${WH}HTTP CUSTOM${COLOR1}: ${WH}$domen:80@$Login:$Pass" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}Payload WS/WSS${COLOR1}: ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1${NC}${WH}GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]User-Agent: [ua][crlf]Upgrade: ws[crlf][crlf]${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}Save Link Acount    : " | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}  ${WH}http://$domen:89/ssh-$Login.txt${NC}$COLOR1 $NC" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ${NC}    ${WH}• SPIDER WEBX STORE •${NC}                 $COLOR1 $NC" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo -e "$COLOR1 ◇━━━━━━━━━━━━━━━━━◇ ${NC}" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
echo "" | tee -a /etc/xray/sshx/akun/log-create-${Login}.log
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
function renew(){
clear
TIMES="10"
CHATID=$(cat /etc/per/id)
KEY=$(cat /etc/per/token)
URL="https://api.telegram.org/bot$KEY/sendMessage"
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
domain=$(cat /etc/xray/domain)
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/ssh")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• RENEW USERS •                    │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1│${WH} User Doesn't Exist!                              $COLOR1   │"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
fi
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• RENEW USERS •                    │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│ ${WH}Please select the user you want to renew.$COLOR1           │"
echo -e "$COLOR1│ ${WH}type [0] back to the menu$COLOR1                        │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
if [[ ${CLIENT_NUMBER} == '1' ]]; then
read -rp "Select one client [1]: " CLIENT_NUMBER
else
read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
if [[ ${CLIENT_NUMBER} == '0' ]]; then
sshws
fi
fi
done
User=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
Pass=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p)
egrep "^$User" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
read -p "Day Extend : " Days
now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(( (d1 - d2) / 86400 ))
exp3=$(($exp2 + $Days))
exp4=`date -d "$exp3 days" +"%Y-%m-%d"`
passwd -u $User
usermod -e  $exp4 $User
egrep "^$User" /etc/passwd >/dev/null
echo -e "$Pass\n$Pass\n"|passwd $User &> /dev/null
sed -i "s/### $User $exp/### $User $exp4/g" /etc/xray/ssh >/dev/null
clear
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  SSH RENEW</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN   :</b> <code>${domain} </code>
<b>ISP      :</b> <code>$ISP $CITY </code>
<b>USERNAME :</b> <code>$User </code>
<b>EXPIRED  :</b> <code>$exp4 </code>
<code>◇━━━━━━━━━━━━━━◇</code>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
user2=$(echo "$User" | cut -c 1-3)
TIME2=$(date +'%Y-%m-%d %H:%M:%S')
TEXT2="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>   SUCCESSFUL TRANSACTION </b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN   :</b> <code>${domain} </code>
<b>ISP      :</b> <code>$CITY </code>
<b>DATE   :</b> <code>${TIME2} WIB</code>
<b>DETAIL   :</b> <code>Trx SSH </code>
<b>USER :</b> <code>${user2}xxx </code>
<b>DURASI  :</b> <code>$Days Hari </code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Renew Account From Server..</i>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID2&disable_web_page_preview=1&text=$TEXT2&parse_mode=html" $URL2 >/dev/null
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• RENEW USERS •                    │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│"
echo -e "$COLOR1│ ${WH}Username   : $User"
echo -e "$COLOR1│ ${WH}Days Added : $Days Days"
echo -e "$COLOR1│ ${WH}Expired on : $exp4"
echo -e "$COLOR1│"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
fi
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
function hapus(){
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/ssh")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• DELETE USERS •                   │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1│${WH} User Doesn't Exist!                              $COLOR1   │"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
fi
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• DELETE USERS •                   │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│ ${WH}Please select the user you want to delete.     $COLOR1      │"
echo -e "$COLOR1│ ${WH}type [0] back to the menu                     $COLOR1   │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
if [[ ${CLIENT_NUMBER} == '1' ]]; then
read -rp "Select one client [1]: " CLIENT_NUMBER
else
read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
if [[ ${CLIENT_NUMBER} == '0' ]]; then
sshws
fi
fi
done
User=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
Days=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
Pass=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p)
sed -i "/^### $User $Days $Pass/d" /etc/xray/ssh
rm /home/vps/public_html/ssh-$User.txt >/dev/null 2>&1
rm /etc/xray/sshx/${User}IP >/dev/null 2>&1
rm /etc/xray/sshx/${User}login >/dev/null 2>&1
if getent passwd $User > /dev/null 2>&1; then
userdel $User > /dev/null 2>&1
echo -e "User $User was removed."
else
echo -e "Failure: User $User Not Exist."
fi
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  DELETE SSH OVPN</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN   :</b> <code>${domain} </code>
<b>ISP      :</b> <code>$ISP $CITY </code>
<b>USERNAME :</b> <code>$User </code>
<b>EXPIRED  :</b> <code>$Days </code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Succes Delete This User...</i>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
function cekconfig(){
ISP=$(cat /etc/xray/isp)
CITY=$(cat /etc/xray/city)
author=$(cat /etc/profil)
IP=$(curl -sS ifconfig.me);
domen=`cat /etc/xray/domain`
sldomain=`cat /etc/xray/dns`
slkey=`cat /etc/slowdns/server.pub`
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/ssh")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• USER CONFIG •                    │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1│${WH} User Doesn't Exist!                              $COLOR1   │"
echo -e "$COLOR1│                                                 │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
fi
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}              ${WH}• USER CONFIG •                    │${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│ ${WH}Please select the user you want to check     $COLOR1         │"
echo -e "$COLOR1│ ${WH}type [0] back to the menu                     $COLOR1   │"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
if [[ ${CLIENT_NUMBER} == '1' ]]; then
read -rp "Select one client [1]: " CLIENT_NUMBER
else
read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
if [[ ${CLIENT_NUMBER} == '0' ]]; then
sshws
fi
fi
done
Login=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
cat /etc/xray/sshx/akun/log-create-${Login}.log
cat /etc/xray/sshx/akun/log-create-${Login}.log > /etc/notifakun
sed -i 's/\x1B\[1;37m//g' /etc/notifakun
sed -i 's/\x1B\[0;96m//g' /etc/notifakun
sed -i 's/\x1B\[0m//g' /etc/notifakun
TEXT=$(cat /etc/notifakun)
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
read -n 1 -s -r -p "   Press any key to back on menu"
menu
}
function hapuslama(){
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1 ${NC} ${COLBG1}                 ${WH}• MEMBER SSH •                 ${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo "USERNAME          EXP DATE          STATUS"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
while read expired
do
ACCOUNT="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $ACCOUNT | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $ACCOUNT | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" "$ACCOUNT" "$exp     " "LOCKED"
else
printf "%-17s %2s %-17s %2s \n" "$ACCOUNT" "$exp     " "UNLOCKED"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo "Account number: $JUMLAH user"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1 ${NC}${COLBG1}              ${WH}• DELETE USERS •                   ${NC}$COLOR1$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo ""
read -p "Username SSH to Delete : " User
if getent passwd $User > /dev/null 2>&1; then
userdel $User > /dev/null 2>&1
echo -e "User $User was removed."
else
echo -e "Failure: User $User Not Exist."
fi
sed -i "/^### $User/d" /etc/xray/ssh
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
function cek(){

if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi
                
data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
echo -e "\033[1;36m┌──────────────────────────────────────────┐\033[0m"
echo "    ID  |  Username  |  IP Address";
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
            cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
            NUM=`cat /tmp/login-db-pid.txt | wc -l`;
            USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
            IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
            if [ $NUM -eq 1 ]; then
                    echo "$PID - $USER - $IP";
                    fi
done
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
echo " "
echo -e "\033[1;36m┌──────────────────────────────────────────┐\033[0m"
echo "    ID  |  Username  |  IP Address";
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);

for PID in "${data[@]}"
do
            cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
            NUM=`cat /tmp/login-db-pid.txt | wc -l`;
            USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
            IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
            if [ $NUM -eq 1 ]; then
                    echo "$PID - $USER - $IP";
        fi
done
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
echo ""
echo -e "\033[1;36m┌──────────────────────────────────────────┐\033[0m"
echo "    Username  |  IP Address  |  Connected";
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
            cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-tcp.txt
            cat /tmp/vpn-login-tcp.txt
fi
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"

if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
echo " "
echo -e "\033[1;36m┌──────────────────────────────────────────┐\033[0m"
echo "    Username  |  IP Address  |  Connected";
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
            cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-udp.txt
            cat /tmp/vpn-login-udp.txt
fi
echo -e "\033[1;36m└──────────────────────────────────────────┘\033[0m"
echo ""
}
function limitssh(){
cd
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/ssh")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
clear
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "$COLOR1 ${NC}${COLBG1}    ${WH}⇱ Limit SSH Account ⇲        ${NC} $COLOR1 $NC"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "You have no existing clients!"
echo ""
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
fi
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "$COLOR1 ${NC}${COLBG1}    ${WH}⇱ Limit SSH Account ⇲        ${NC} $COLOR1 $NC"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "Select the existing client you want to change ip"
echo " type [0] back to the menu"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
if [[ ${CLIENT_NUMBER} == '1' ]]; then
read -rp "Select one client [1]: " CLIENT_NUMBER
else
read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
if [[ ${CLIENT_NUMBER} == '0' ]]; then
sshws
fi
fi
done
until [[ $iplim =~ ^[0-9]+$ ]]; do
read -p "Limit User (IP) New: " iplim
done
if [ ! -e /etc/xray/sshx ]; then
mkdir -p /etc/xray/sshx
fi
if [ -z ${iplim} ]; then
iplim="0"
fi
user=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/ssh" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
echo "${iplim}" >/etc/xray/sshx/${user}IP
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  SSH IP LIMIT</b>
<code>◇━━━━━━━━━━━━━━◇</code>
<b>DOMAIN   :</b> <code>${domain} </code>
<b>ISP      :</b> <code>$ISP $CITY </code>
<b>USERNAME :</b> <code>$user </code>
<b>EXPIRED  :</b> <code>$exp </code>
<b>IP LIMIT NEW :</b> <code>$iplim IP </code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Succes Change IP LIMIT...</i>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
clear
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo " SSH Account Was Successfully Change Limit IP"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo " Client Name : $user"
echo " Limit IP    : $iplim IP"
echo ""
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
clear
function listssh(){
clear
echo -e "$COLOR1┌──────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│ \033[1;37mPlease select a your Choice              $COLOR1│${NC}"
echo -e "$COLOR1└──────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌──────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│  [ 1 ]  \033[1;37mAUTO LOCKED USER SSH      ${NC}"
echo -e "$COLOR1│  "
echo -e "$COLOR1│  [ 2 ]  \033[1;37mAUTO DELETE USER SSH    ${NC}"
echo -e "$COLOR1│  "
echo -e "$COLOR1│  "
echo -e "$COLOR1│  [ 0 ]  \033[1;37mBACK TO MENU    ${NC}"
echo -e "$COLOR1└──────────────────────────────────────────┘${NC}"
until [[ $lock =~ ^[0-2]+$ ]]; do
read -p "   Please select numbers 1 sampai 2 : " lock
done
if [[ $lock == "0" ]]; then
menu
elif [[ $lock == "1" ]]; then
clear
echo "lock" > /etc/typessh
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│$NC Successful Auto Lock Replacement  ${NC}"
echo -e "$COLOR1│$NC If the User Violates the Account auto lock. ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
sleep 1
elif [[ $lock == "2" ]]; then
clear
echo "delete" > /etc/typessh
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│$NC Success Change Auto Delete AccounT ${NC}"
echo -e "$COLOR1│$NC If User Violates Auto Delete Account. ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
sleep 1
fi
type=$(cat /etc/typessh)
if [ $type = "lock" ]; then
clear
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│$NC PLEASE WRITE THE AMOUNT OF TIME TO BE LOCKED  ${NC}"
echo -e "$COLOR1│$NC CAN WRITE 15 MINUTES ETC.. ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
read -rp "   Jumlah Waktu Lock: " -e notif2
echo "${notif2}" > /etc/waktulockssh
clear
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "${COLOR1}│ $NC PLEASE WRITE THE NUMBER OF NOTIFICATIONS FOR AUTO LOCK   ${NC}"
echo -e "${COLOR1}│ $NC MULTI-LOGIN USER ACCOUNT     ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
read -rp "   Jika Mau 3x Notif baru kelock tulis 3, dst: " -e notif
cd /etc/xray/sshx
echo "$notif" > notif
clear
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "${COLOR1}│ $NC SUCCESSFULLY CHANGE NOTIF LOCK TO $notif $NC "
echo -e "${COLOR1}│ $NC SUCCESSFULLY CHANGE TIME NOTIF LOCK TO BE $notif2 MENIT $NC "
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
else
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│$NC PLEASE WRITE THE AMOUNT OF TIME TO SCAN ${NC}"
echo -e "$COLOR1│$NC MULTI LOGGED USERS . ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
read -rp "   Tulis Waktu Scan (Menit) : " -e notif2
echo "# Autokill" >/etc/cron.d/tendang
echo "SHELL=/bin/sh" >>/etc/cron.d/tendang
echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >>/etc/cron.d/tendang
echo "*/$notif2 * * * *  root /usr/bin/tendang" >>/etc/cron.d/tendang
clear
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "${COLOR1}│ $NC PLEASE WRITE THE NUMBER OF NOTIFICATIONS FOR AUTO LOCK    ${NC}"
echo -e "${COLOR1}│ $NC MULTI-LOGIN USER ACCOUNT     ${NC}"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
read -rp "   If you want 3x new notifications to lock, write 3, etc.: " -e notif
cd /etc/xray/sshx
echo "$notif" > notif
clear
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}${COLBG1}           ${WH}• SETTING MULTI LOGIN •             ${NC}$COLOR1│ $NC"
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e "${COLOR1}│ $NC SUCCESSFULLY CHANGE NOTIF LOCK TO $notif $NC "
echo -e "${COLOR1}│ $NC SUCCESSFULLY CHANGE TIME NOTIF LOCK TO BE $notif2 MENIT $NC "
echo -e "$COLOR1└───────────────────────────────────────────────┘${NC}"
fi
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
function lockssh(){
clear
cd
if [ ! -e /etc/xray/sshx/listlock ]; then
echo "" > /etc/xray/sshx/listlock
fi
NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/etc/xray/sshx/listlock")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "$COLOR1 ${NC}${COLBG1}    ${WH}⇱ Unlock SSH Account ⇲       ${NC} $COLOR1 $NC"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "You have no existing user Lock!"
echo ""
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
read -n 1 -s -r -p "Press any key to back on menu"
sshws
fi
clear
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "$COLOR1 ${NC}${COLBG1}    ${WH}⇱ Unlock SSH Account ⇲       ${NC} $COLOR1 $NC"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo " Select the existing client you want to Unlock"
echo " type [0] back to the menu"
echo " tulis clear untuk delete semua Akun"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "     No  User      Expired"
grep -E "^### " "/etc/xray/sshx/listlock" | cut -d ' ' -f 2-3 | nl -s ') '
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
if [[ ${CLIENT_NUMBER} == '1' ]]; then
read -rp "Select one client [1]: " CLIENT_NUMBER
else
read -rp "Select one client [1-${NUMBER_OF_CLIENTS}] to Unlock: " CLIENT_NUMBER
if [[ ${CLIENT_NUMBER} == '0' ]]; then
sshws
fi
if [[ ${CLIENT_NUMBER} == 'clear' ]]; then
rm /etc/xray/sshx/listlock
sshws
fi
fi
done
user=$(grep -E "^### " "/etc/xray/sshx/listlock" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p)
exp=$(grep -E "^### " "/etc/xray/sshx/listlock" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
pass=$(grep -E "^### " "/etc/xray/sshx/listlock" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p)
passwd -u $user &> /dev/null
echo -e "### $Login $exp $Pass" >> /etc/xray/ssh
sed -i "/^### $user $exp $pass/d" /etc/xray/sshx/listlock &> /dev/null
TEXT="
<code>◇━━━━━━━━━━━━━━◇</code>
<b>  SSH UNLOK </b>
<code>◇━━━━━━━━━━━━━━◇
<b>DOMAIN   :</b> <code>${domain} </code>
<b>ISP      :</b> <code>$ISP $CITY </code>
<b>USERNAME :</b> <code>$user </code>
<b>IP LIMIT  :</b> <code>$iplim IP </code>
<b>EXPIRED  :</b> <code>$exp </code>
<code>◇━━━━━━━━━━━━━━◇</code>
<i>Succes Unlock Akun...</i>
"
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cd
if [ ! -e /etc/tele ]; then
echo -ne
else
echo "$TEXT" > /etc/notiftele
bash /etc/tele
fi
clear
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo " SSH Account Unlock Successfully"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo " Client Name : $user"
echo " Status  : Unlocked"
echo -e "$COLOR1━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
sshws
}
clear
author=$(cat /etc/profil)
echo -e " $COLOR1╔══════════════════════════════════════╗${NC}"
echo -e " $COLOR1║${NC}${COLBG1} ${WH}•SSH PANEL MENU•${NC}$COLOR1║ $NC"
echo -e " $COLOR1╚══════════════════════════════════════╝${NC}"
echo -e " $COLOR1╔══════════════════════════════════════╗${NC}"
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}01${WH}]${NC} ${COLOR1}• ${WH}ADD ACCOUNT${NC}"         
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}02${WH}]${NC} ${COLOR1}• ${WH}TRIAL ACCOUNT${NC}"      
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}03${WH}]${NC} ${COLOR1}• ${WH}RENEW ACCOUNT${NC}"      
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}04${WH}]${NC} ${COLOR1}• ${WH}DELETE ACCOUNT${NC}"
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}05${WH}]${NC} ${COLOR1}• ${WH}CEK LOGIN USER${NC}"      
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}06${WH}]${NC} ${COLOR1}• ${WH}CEK USER CONFIG${NC}"      
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}07${WH}]${NC} ${COLOR1}• ${WH}CHANGE IP LIMIT${NC}"       
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}08${WH}]${NC} ${COLOR1}• ${WH}SETTING LOCK LOGIN${NC}"    
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}09${WH}]${NC} ${COLOR1}• ${WH}UNLOCK LOGIN${NC}" 
echo -e " $COLOR1║ $NC  ${WH}[${COLOR1}00${WH}]${NC} ${COLOR1}• ${WH}GO BACK${NC}"     
echo -e " $COLOR1╚══════════════════════════════════════╝${NC}"
echo -e " $COLOR1╔═══════════════${WH}BY${NC} ${COLOR1}══════════════╗ ${NC}"
echo -e " $COLOR1${NC}${WH}  • SPIDER WEBX STORE •     $COLOR1 $NC"
echo -e " $COLOR1╚═════════════════════════════════════╝${NC}"
echo -e ""
echo -ne " ${WH}Select menu ${COLOR1}: ${WH}"; read opt
case $opt in
01 | 1) clear ; usernew  ;;
02 | 2) clear ; trial  ;;
03 | 3) clear ; renew  ;;
04 | 4) clear ; hapus  ;;
05 | 5) clear ; cek  ;;
06 | 6) clear ; cekconfig  ;;
07 | 7) clear ; limitssh ;;
08 | 8) clear ; listssh  ;;
09 | 9) clear ; lockssh  ;;
10 | 10) clear ; hapuslama  ;;
00 | 0) clear ; menu  ;;
X  | 0) clear ; sshws ;;
x) exit ;;
*) echo "You pressed it wrong " ; sleep 1 ; sshws ;;
esac
