#!/usr/bin/env sh
# サンプルSSHログを /ingest に投入（Linux/Mac/Git Bash）
# 使い方:  ./scripts/send_sample.sh
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
AUTH=""
[ -n "$INGEST_TOKEN" ] && AUTH="-H \"Authorization: Bearer $INGEST_TOKEN\""
curl -s -X POST "http://localhost:8000/ingest" \
  -H "Content-Type: application/json" \
  ${INGEST_TOKEN:+-H "Authorization: Bearer $INGEST_TOKEN"} \
  --data-binary "@${DIR}/backend/samples/ssh_sample.json"
echo
