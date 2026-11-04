#!/bin/bash
# Memasang agen penarik ban IP Beruk Sakti di server tujuan (mis. webserver-ubuntu-01). Jalankan sebagai root:
#   sudo bash install.sh --url https://wazuh.toyspedia.fun/soc-automation/api/ban-feed --host webserver-ubuntu-01 \
#        --allow 43.133.142.174,43.173.12.72,125.165.60.10
# Token diminta secara tersembunyi (tidak tampil dan tidak masuk riwayat shell). Hapus semuanya: sudo bash install.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")"

URL=""; HOST="$(hostname)"; ALLOW=""; BANACTION=""; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2;;
    --host) HOST="$2"; shift 2;;
    --allow) ALLOW="$2"; shift 2;;
    --banaction) BANACTION="$2"; shift 2;;
    --uninstall) UNINSTALL=1; shift;;
    *) echo "Argumen tidak dikenal: $1"; exit 2;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now soc-ban-agent 2>/dev/null || true
  rm -f /etc/systemd/system/soc-ban-agent.service /usr/local/sbin/soc-ban-agent
  rm -f /etc/fail2ban/jail.d/beruk-feed.local /etc/fail2ban/filter.d/beruk-feed.conf
  rm -rf /etc/soc-ban-agent
  systemctl daemon-reload
  fail2ban-client reload >/dev/null 2>&1 || true
  echo "Agen dihapus. Ban yang sempat dipasang di jail beruk-feed ikut hilang saat jail dimuat ulang."
  exit 0
fi

[ -n "$URL" ] || { echo "Wajib: --url https://.../api/ban-feed"; exit 2; }
case "$URL" in https://*) ;; *) echo "URL harus https://"; exit 2;; esac
command -v python3 >/dev/null || { echo "python3 tidak ada"; exit 1; }
command -v fail2ban-client >/dev/null || { echo "fail2ban tidak terpasang di server ini"; exit 1; }
systemctl is-active --quiet fail2ban || { echo "layanan fail2ban tidak aktif"; exit 1; }

# Pilih banaction sesuai firewall yang dipakai server ini.
if [ -z "$BANACTION" ]; then
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then BANACTION="ufw[blocktype=deny]"
  elif command -v nft >/dev/null; then BANACTION="nftables[type=allports]"
  else BANACTION="iptables-allports"; fi
fi
echo "banaction: $BANACTION"

ALLOW_JSON=$(python3 - "$ALLOW" <<'PY'
import json, sys
print(json.dumps([x.strip() for x in sys.argv[1].split(",") if x.strip()]))
PY
)

install -d -m 700 -o root -g root /etc/soc-ban-agent
python3 - "$URL" "$HOST" "$ALLOW_JSON" <<'PY'
import json, sys
cfg = {"url": sys.argv[1], "token_file": "/etc/soc-ban-agent/token", "jail": "beruk-feed", "host": sys.argv[2],
       "allowlist": json.loads(sys.argv[3]), "max_active": 200, "max_bans_per_cycle": 25, "interval": 15}
json.dump(cfg, open("/etc/soc-ban-agent/config.json", "w"), indent=2)
PY
chmod 600 /etc/soc-ban-agent/config.json

if [ ! -s /etc/soc-ban-agent/token ]; then
  read -rsp "Tempel token feed dari dashboard (tidak tampil): " TOKEN; echo
  [ "${#TOKEN}" -ge 32 ] || { echo "Token terlalu pendek (minimal 32 karakter)."; exit 1; }
  ( umask 077; printf '%s\n' "$TOKEN" > /etc/soc-ban-agent/token )
  unset TOKEN
fi
chown root:root /etc/soc-ban-agent/token; chmod 600 /etc/soc-ban-agent/token

install -o root -g root -m 750 soc-ban-agent /usr/local/sbin/soc-ban-agent
install -o root -g root -m 644 soc-ban-agent.service /etc/systemd/system/soc-ban-agent.service
install -o root -g root -m 644 beruk-feed.conf /etc/fail2ban/filter.d/beruk-feed.conf
sed "s#BANACTION_DIISI_INSTALLER#${BANACTION}#" beruk-feed.local > /etc/fail2ban/jail.d/beruk-feed.local
chmod 644 /etc/fail2ban/jail.d/beruk-feed.local

fail2ban-client -t >/dev/null 2>&1 || { echo "Uji konfigurasi fail2ban GAGAL; periksa /etc/fail2ban/jail.d/beruk-feed.local"; fail2ban-client -t; exit 1; }
fail2ban-client reload
sleep 2
fail2ban-client status beruk-feed >/dev/null || { echo "Jail beruk-feed tidak aktif setelah reload"; exit 1; }

systemctl daemon-reload
systemctl enable --now soc-ban-agent
sleep 4
echo "--- status"
systemctl is-active soc-ban-agent
journalctl -u soc-ban-agent -n 8 --no-pager | cut -c1-200
echo "--- jail"
fail2ban-client status beruk-feed
