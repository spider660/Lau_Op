#!/usr/bin/env bash
# spider_wrapper.sh - compatibility shim to run original spider.sh without modifying it
# This wrapper makes minimal, reversible environment changes:
# - ensures 'python' points to 'python3' in /usr/local/bin if no python exists
# - ensures chrony or systemd-timesyncd is present for time sync
# - provides a 'service' fallback that maps to systemctl where possible
#
# Usage: sudo ./spider_wrapper.sh

set -euo pipefail

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root"
  exit 1
fi

# 1) Provide 'python' shim if missing (non-destructive)
if ! command -v python >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    if [[ ! -f /usr/local/bin/python ]]; then
      echo "Creating /usr/local/bin/python -> python3 shim"
      cat >/usr/local/bin/python <<'PY'
#!/usr/bin/env bash
exec python3 "$@"
PY
      chmod +x /usr/local/bin/python
    fi
  fi
fi

# 2) Ensure chrony or systemd-timesyncd installed
if ! command -v chronyd >/dev/null 2>&1 && ! command -v chronyc >/dev/null 2>&1; then
  echo "Installing chrony for time sync (apt-get)"
  apt-get update -y
  apt-get install -y chrony || true
  systemctl enable --now chrony || true
fi

# 3) Provide service -> systemctl fallback function in environment
service(){
  # usage: service name action
  local name="$1"
  local action="$2"
  if systemctl list-units --full -all | grep -Fq "${name}.service"; then
    systemctl "${action}" "${name}.service"
  else
    # try old-style service command if present
    if command -v /usr/sbin/service >/dev/null 2>&1; then
      /usr/sbin/service "${name}" "${action}"
    else
      echo "Service ${name} ${action} (no systemctl/service found) - ignoring"
      return 0
    fi
  fi
}

# 4) Run the original installer (spider.sh) in this repo
if [[ -f "./spider.sh" ]]; then
  echo "Running spider.sh via wrapper..."
  exec bash ./spider.sh
else
  echo "spider.sh not found in current directory"
  exit 1
fi
