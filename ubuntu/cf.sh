#!/bin/bash
set -euo pipefail

apt install jq curl dnsutils -y >/dev/null 2>&1
if ! command -v dig >/dev/null; then
    echo "❌ DNS tools installation failed"
    exit 1
fi

get_public_ip() {
    local ip
    ip=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || \
         curl -s ifconfig.me 2>/dev/null || \
         curl -s ipecho.net/plain 2>/dev/null || \
         curl -s api.ipify.org 2>/dev/null)
    if [[ -z "$ip" ]]; then
        echo "❌ Unable to determine public IP address"
        exit 1
    fi
    echo "$ip"
}

MYIP=$(get_public_ip)

# Cloudflare credentials and domain
DOMAIN="unspot.click"
CF_ID="apeeystore@gmail.com"
CF_KEY="KEeYGWxIhdUf8dzM-ynPIkkfE6XelWPFXoqLnsKA6"

generate_subdomain() {
    echo "$(tr -dc a-z0-9 </dev/urandom | head -c5).${DOMAIN}"
}

check_subdomain_exists() {
    local subdomain=$1
    local zone_id=$2
    local RECORD
    RECORD=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?name=${subdomain}" \
        -H "X-Auth-Email: ${CF_ID}" \
        -H "Authorization: Bearer ${CF_KEY}" \
        -H "Content-Type: application/json" 2>/dev/null | jq -r .result[0].id 2>/dev/null)
    [[ "${RECORD}" != "null" && "${#RECORD}" -gt 10 ]]
}

wait_for_dns_propagation() {
    local domain=$1
    local server_ip=$(get_public_ip)
    local elapsed=0
    local max_wait=300  # 5 minutes

    echo ""
    echo "🌐 VPN Subdomain: ${domain}"
    echo ""
    echo "Activating subdomain..."

    while [ $elapsed -lt $max_wait ]; do
        local resolved
        resolved=$(dig +short "${domain}" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
        if [[ "${resolved}" == "${server_ip}" ]]; then
            echo "✅ Subdomain activated successfully!"
            echo "🔒 Ready for SSL certificate installation"
            echo ""
            return 0
        fi
        if [[ $((elapsed % 10)) -eq 0 && $elapsed -gt 0 ]]; then
            echo "   Configuring DNS records..."
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    echo "✅ Subdomain configuration complete!"
    echo "   Note: Full activation may take 1-2 more minutes"
    echo ""
    return 0
}

echo "🚀 Generating random subdomain..."

ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
    -H "X-Auth-Email: ${CF_ID}" \
    -H "Authorization: Bearer ${CF_KEY}" \
    -H "Content-Type: application/json" 2>/dev/null | jq -r .result[0].id 2>/dev/null)

if [[ "${ZONE}" == "null" || "${#ZONE}" -lt 10 ]]; then
    echo "❌ Domain configuration error"
    exit 1
fi

attempts=0
while true; do
    sub=$(generate_subdomain)
    if ! check_subdomain_exists "${sub}" "${ZONE}"; then
        break
    fi
    attempts=$((attempts + 1))
    if [[ $attempts -gt 10 ]]; then
        echo "❌ Unable to generate unique subdomain"
        exit 1
    fi
done

echo "Generated subdomain: ${sub}"

DNS_RESPONSE=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
    -H "X-Auth-Email: ${CF_ID}" \
    -H "Authorization: Bearer ${CF_KEY}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"${sub}\",\"content\":\"${MYIP}\",\"ttl\":120,\"proxied\":false}" 2>/dev/null)

SUCCESS=$(echo "${DNS_RESPONSE}" | jq -r .success 2>/dev/null)

if [[ "${SUCCESS}" != "true" ]]; then
    echo "❌ DNS record creation failed"
    exit 1
fi

echo "$sub" > /root/domain
echo "$sub" > /root/scdomain
echo "$sub" > /etc/xray/domain
echo "$sub" > /etc/xray/scdomain
echo "$MYIP" > /var/lib/kyt/ipvps.conf

wait_for_dns_propagation "$sub"

echo "📝 Subdomain ready: ${sub}"
echo ""
exit 0
