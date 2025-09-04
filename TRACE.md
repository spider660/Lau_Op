# Lau_Op Trace Report
_Generated: 2025-09-02 19:00:45 UTC_

## Summary
- Root: `/mnt/data/Lau_Op-main/Lau_Op-main`
- Total scripts scanned: **73**
- Systemd service units: **11**

## Menu Entrypoint
- Found main menu at: `ubuntu/menu/menu/menu.sh`

## Scripts
### `kyt.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- Detected dependencies: chmod, git, python3, python3-pip, service, systemctl, unzip, wget, zip

### `spider.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- IP/permission indicators: \bIPVPS\b, \bMYIP\b, \biptables\b, \bufw\b, curl\s+-s\s+ifconfig\.me, icanhazip, ipinfo\.io
- Detected dependencies: 2>&1, >/dev/null, awk, chmod, chown, cron, curl, dnsutils, git, grep, ifconfig, ip, iptables, jq, lsof, net-tools, python3, sed, service, socat, systemctl, true, ufw, unzip, wget, zip, ||

### `ubuntu/bbr.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- Detected dependencies: grep

### `ubuntu/cf.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- Detected dependencies: ps, python, service, ss

### `ubuntu/limit.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- Detected dependencies: ss, wget

### `ubuntu/menu/menu/menu.sh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Script calls:
  - `exec` → `./install-udp`
  - `exec` → `./update.sh`
- Local helper invokes: add-bot-panel, addhost, autoreboot, bot, bw, clearcache, clearlog, fixcert, limitspeed, m-sshws, m-ssws, m-trojan, m-vless, m-vmess, menu-backup, prot, restart, run, sd, speedtest, xp
- IP/permission indicators: \bIPVPS\b, \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, chmod, curl, grep, ps, sed, ss, systemctl, wget

### `ubuntu/udp.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**

### `update.sh`
- Shebang: `#!/usr/bin/env bash`
- Executable: **True**
- Detected dependencies: chmod, curl, grep, sed, service, unzip, wget, zip

### `ubuntu/menu/menu/add-bot-notif`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, grep, sed

### `ubuntu/menu/menu/add-bot-panel`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Script calls:
  - `exec` → `./kyt.sh`
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: awk, chmod, curl, grep, sed, systemctl, wget

### `ubuntu/menu/menu/addhost`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Script calls:
  - `shell` → `/root/.acme.sh/acme.sh`
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, chmod, curl, grep, lsof, sed, systemctl, wget

### `ubuntu/menu/menu/addss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, sed, service, ss, systemctl, wget

### `ubuntu/menu/menu/addssh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/addtr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: m-trojan
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, sed, service, systemctl, wget

### `ubuntu/menu/menu/addvless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, systemctl, wget

### `ubuntu/menu/menu/addws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, ps, sed, service, systemctl, wget

### `ubuntu/menu/menu/autokill`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep

### `ubuntu/menu/menu/autoreboot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: autoreboot
- IP/permission indicators: \bMYIP\b, icanhazip
- Detected dependencies: chmod, wget

### `ubuntu/menu/menu/backup`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: icanhazip
- Detected dependencies: curl, grep, zip

### `ubuntu/menu/menu/bot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: add-bot-notif, del-bot-notif
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/bw`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: bw
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: wget

### `ubuntu/menu/menu/ceklim`
- Shebang: `#!/bin/bash`
- Executable: **True**

### `ubuntu/menu/menu/cekss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, ip, sed

### `ubuntu/menu/menu/cekssh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, grep, ps, sed

### `ubuntu/menu/menu/cektr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, ip, sed

### `ubuntu/menu/menu/cekvless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, ip, sed

### `ubuntu/menu/menu/cekws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, ip, sed

### `ubuntu/menu/menu/clearcache`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: curl, grep, wget

### `ubuntu/menu/menu/clearlog`
- Shebang: `#!/bin/bash`
- Executable: **True**

### `ubuntu/menu/menu/del-bot-notif`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/delexp`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, sed

### `ubuntu/menu/menu/delss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/delssh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, grep

### `ubuntu/menu/menu/deltr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: m-trojan
- Detected dependencies: curl, grep, sed, systemctl

### `ubuntu/menu/menu/delvless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/delws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: curl, grep, sed, systemctl

### `ubuntu/menu/menu/fixcert`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Script calls:
  - `shell` → `/root/.acme.sh/acme.sh`
- Detected dependencies: awk, chmod, curl, grep, lsof, systemctl

### `ubuntu/menu/menu/hapus-bot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: curl, grep, sed, service, zip

### `ubuntu/menu/menu/limitspeed`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: awk, curl, grep, ip, service, systemctl, wget

### `ubuntu/menu/menu/m-sshws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: addssh, autokill, ceklim, cekssh, delexp, delssh, member, renewssh, trial, user-ssh
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/m-ssws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: addss, cekss, delss, renewss, trialss, user-ss
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/m-trojan`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: addtr, cektr, deltr, renewtr, trialtr, user-tr
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/m-vless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: addvless, cekvless, delvless, renewvless, trialvless, user-vless
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/m-vmess`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: addws, cekws, delws, renewws, trialws, user-ws
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/mbot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip
- Detected dependencies: awk, cron, curl, grep, sed, service, unzip, wget, zip

### `ubuntu/menu/menu/member`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: awk, grep, wget

### `ubuntu/menu/menu/menu-backup`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, wget

### `ubuntu/menu/menu/prot`
- Shebang: `#!/bin/bash`
- Executable: **True**

### `ubuntu/menu/menu/renewss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/renewssh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, ipinfo\.io
- Detected dependencies: awk, grep, wget

### `ubuntu/menu/menu/renewtr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/renewvless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/renewws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, systemctl

### `ubuntu/menu/menu/reset`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: cron, service, systemctl

### `ubuntu/menu/menu/restart`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: systemctl

### `ubuntu/menu/menu/restart-bot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: add-bot-panel
- Detected dependencies: service, systemctl

### `ubuntu/menu/menu/restore`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: crontab, curl, grep, unzip, wget, zip

### `ubuntu/menu/menu/run`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bIPVPS\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, sed, service, ss, systemctl

### `ubuntu/menu/menu/sd`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: ipinfo\.io
- Detected dependencies: awk, curl, grep, ifconfig, netstat, sed, wget

### `ubuntu/menu/menu/speedtest`
- Shebang: _none_
- Executable: **True**
- IP/permission indicators: \bip\b\s+(address|rule|tables?)
- Detected dependencies: ip, service

### `ubuntu/menu/menu/stop-bot`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Local helper invokes: add-bot-panel
- Detected dependencies: service, systemctl

### `ubuntu/menu/menu/tendang`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, grep, ps, sed, service

### `ubuntu/menu/menu/trial`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed

### `ubuntu/menu/menu/trialss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, sed, service, ss, systemctl, wget

### `ubuntu/menu/menu/trialtr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, sed, service, systemctl, wget

### `ubuntu/menu/menu/trialvless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, curl, grep, sed, systemctl, wget

### `ubuntu/menu/menu/trialws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- IP/permission indicators: \bMYIP\b, icanhazip, ipinfo\.io
- Detected dependencies: awk, cron, curl, grep, ps, sed, service, systemctl, wget

### `ubuntu/menu/menu/user-ss`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed, ss

### `ubuntu/menu/menu/user-ssh`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: curl, grep, ifconfig, sed

### `ubuntu/menu/menu/user-tr`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed

### `ubuntu/menu/menu/user-vless`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, sed

### `ubuntu/menu/menu/user-ws`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: grep, ps, sed

### `ubuntu/menu/menu/xp`
- Shebang: `#!/bin/bash`
- Executable: **True**
- Detected dependencies: awk, grep, sed, systemctl

## Systemd Service Units
- `ubuntu/dropbear.service`
- `ubuntu/limitshadowsocks.service`
- `ubuntu/limittrojan.service`
- `ubuntu/limitvless.service`
- `ubuntu/limitvmess.service`
- `ubuntu/runn.service`
- `ubuntu/socks.service`
- `ubuntu/udp-mini-1.service`
- `ubuntu/udp-mini-2.service`
- `ubuntu/udp-mini-3.service`
- `ubuntu/ws.service`

## Consolidated Dependencies (Ubuntu/Debian)
Install these first to ensure smooth run:
```bash
apt-get update && apt-get install -y 2>&1 >/dev/null awk chmod chown cron crontab curl dnsutils git grep ifconfig ip iptables jq lsof net-tools netstat ps python python3 python3-pip sed service socat ss systemctl true ufw unzip wget zip ||
```

## Compatibility Notes
- Designed for **systemd-based** Ubuntu (18.04+) and Debian (10+).
- Requires `/bin/bash` (scripts use bashisms).
- Expects `wget`/`curl`/`unzip` available to fetch and unpack menu bundle.
- Uses cron via `/etc/cron.d/` files in installer.
