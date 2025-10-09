#!/usr/bin/env bash
# safer Cloudflare DNS updater
set -euo pipefail

# --- CONFIG: set these ---
DOMAIN="spiderwebx.store"
sub=$(</dev/urandom tr -dc a-z0-9 | head -c5)
dns="${sub}.${DOMAIN}"
CF_ID=bluespiders123@gmail.com
CF_KEY=19PVGfECMPSCIg_tUMaY5yUMBgUymuWO-WfNRGbk
: "${CF_TOKEN:?Need to set CF_TOKEN environment variable (Cloudflare API Token)}"

# --- helper functions ---
info(){ printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn(){ printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err(){ printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }

# get current public IP
info "Detecting public IPv4..."
IP="$(curl -fsS --max-time 10 https://ipv4.icanhazip.com || true)"
IP="${IP//[$'\n\r']}"   # strip newline
if [[ -z "$IP" ]]; then
  err "Could not detect public IP. Exiting."
  exit 1
fi
info "Public IP: $IP"

# get zone id
info "Generating a new domain..."
info "Fetching Cloudflare zone id for ${DOMAIN}..."
ZONE_JSON=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json")
ZONE_ID=$(printf '%s' "$ZONE_JSON" | jq -r '.result[0].id // empty')

if [[ -z "$ZONE_ID" ]]; then
  err "Could not find zone id for ${DOMAIN}. Raw response:"
  printf '%s\n' "$ZONE_JSON"
  exit 1
fi
info "Zone ID: $ZONE_ID"

# check existing record
info "Checking for existing A record for ${dns}..."
RECS_JSON=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=${dns}" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -H "Content-Type: application/json")
REC_ID=$(printf '%s' "$RECS_JSON" | jq -r '.result[0].id // empty')

if [[ -z "$REC_ID" ]]; then
  info "No existing record found — creating A record ${dns} -> ${IP}"
  CREATE_JSON=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"${dns}\",\"content\":\"${IP}\",\"ttl\":120,\"proxied\":false}")
  success=$(printf '%s' "$CREATE_JSON" | jq -r '.success')
  if [[ "$success" != "true" ]]; then
    err "Failed to create record. Response:"
    printf '%s\n' "$CREATE_JSON"
    exit 1
  fi
  REC_ID=$(printf '%s' "$CREATE_JSON" | jq -r '.result.id')
  info "Created record id: ${REC_ID}"
else
  info "Existing record id ${REC_ID} found — updating to ${IP}"
  UPDATE_JSON=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${REC_ID}" \
    -H "Authorization: Bearer ${CF_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"A\",\"name\":\"${dns}\",\"content\":\"${IP}\",\"ttl\":120,\"proxied\":false}")
  success=$(printf '%s' "$UPDATE_JSON" | jq -r '.success')
  if [[ "$success" != "true" ]]; then
    err "Failed to update record. Response:"
    printf '%s\n' "$UPDATE_JSON"
    exit 1
  fi
  info "Updated record ${REC_ID} -> ${IP}"
fi

# write domains to files (same as your original script)
echo "$dns" > /root/domain
echo "$dns" > /root/scdomain
echo "$dns" > /etc/xray/domain
echo "$dns" > /etc/v2ray/domain
echo "$dns" > /etc/xray/scdomain
echo "IP=$dns" > /var/lib/kyt/ipvps.conf

info "Done. Created/updated ${dns}"
