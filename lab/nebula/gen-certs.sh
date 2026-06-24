#!/usr/bin/env bash
# Sinh CA + cert lighthouse (responder) + cert client (initiator) cho lab Nebula handshake-interop.
# Yêu cầu: nebula-cert (tải từ github.com/slackhq/nebula releases) cùng thư mục.
# Output: ca.crt/ca.key + lighthouse.crt/.key + client.crt/.key (KHÔNG commit — xem .gitignore).
set -e
cd "$(dirname "$0")"

NEBULA_CERT=${NEBULA_CERT:-./nebula-cert}

rm -f ca.crt ca.key lighthouse.crt lighthouse.key client.crt client.key

# CA Curve25519 (Ed25519 signing) — mặc định curve 25519.
"$NEBULA_CERT" ca -name "Lab CA" -duration 87600h

# Responder (lighthouse) + initiator (client), cùng overlay 192.168.100.0/24.
"$NEBULA_CERT" sign -name "lighthouse" -ip "192.168.100.1/24"
"$NEBULA_CERT" sign -name "client"     -ip "192.168.100.5/24"

echo "=== generated ==="
ls -la ca.crt lighthouse.crt client.crt client.key
echo "=== client cert ==="
"$NEBULA_CERT" print -path client.crt
