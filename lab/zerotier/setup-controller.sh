#!/usr/bin/env bash
# Configure the running zerotier-one node as a network controller for the V.7.3 live lab:
#   1. read the node's address (= the controller address) and its identity.public (the client's peer identity),
#   2. create a private network on it via the local controller API,
#   3. set the IPv4 auto-assign pool + a managed route (so the controller assigns the client an IP),
#   4. generate a throwaway client identity with zerotier-idtool,
#   5. authorize that client's address as a member with a static IP.
# Exports everything the .NET client needs to /shared. No GPL/BSL source is used — only the public CLI/API.
set -euo pipefail

DATA=/var/lib/zerotier-one
OUT=/shared
mkdir -p "$OUT"

# Wait for the node to be online and to have written its identity + authtoken.
for i in $(seq 1 30); do
  [ -f "$DATA/authtoken.secret" ] && [ -f "$DATA/identity.public" ] && break
  sleep 1
done

TOKEN=$(cat "$DATA/authtoken.secret")
NODE=$(zerotier-cli -j info | grep -o '"address": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{10\}')
NODE_PUBLIC=$(cat "$DATA/identity.public")
echo "[lab] controller node address = $NODE"

API() { curl -s -H "X-ZT1-Auth: $TOKEN" "$@"; }

# 1) Create a network on this controller. The controller address is the high 40 bits of the network id; the local
#    API endpoint /controller/network/<node>______ asks the controller to allocate the low 24 bits itself.
NET_JSON=$(API -X POST "http://localhost:9993/controller/network/${NODE}______" -d '{"name":"ztlab"}')
NWID=$(echo "$NET_JSON" | grep -o '"id": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{16\}')
echo "[lab] created network $NWID"

# 2) Configure the network: private, IPv4 auto-assign pool 10.144.0.0/24, a managed route for the subnet, v4 assign mode.
API -X POST "http://localhost:9993/controller/network/${NWID}" -d '{
  "private": true,
  "v4AssignMode": {"zt": true},
  "ipAssignmentPools": [{"ipRangeStart":"10.144.0.2","ipRangeEnd":"10.144.0.50"}],
  "routes": [{"target":"10.144.0.0/24","via":null}]
}' > /dev/null
echo "[lab] network configured (private, pool 10.144.0.2-50, route 10.144.0.0/24)"

# 3) Generate a throwaway client identity (addr:0:pub:priv) and authorize it as a member with a fixed IP.
zerotier-idtool generate "$OUT/client.secret" "$OUT/client.public"
CLIENT=$(cut -d: -f1 "$OUT/client.public")
echo "[lab] client address = $CLIENT"

API -X POST "http://localhost:9993/controller/network/${NWID}/member/${CLIENT}" -d '{
  "authorized": true,
  "ipAssignments": ["10.144.0.2"]
}' > /dev/null
echo "[lab] member $CLIENT authorized with 10.144.0.2"

# 4) Export the lab facts for the .NET client.
echo "$NODE_PUBLIC" > "$OUT/node.public"
{
  echo "node_address=$NODE"
  echo "node_public=$NODE_PUBLIC"
  echo "network=$NWID"
  echo "client_address=$CLIENT"
  echo "client_ip=10.144.0.2"
} > "$OUT/lab.env"

echo "[lab] === setup complete ==="
echo "[lab] network    = $NWID"
echo "[lab] node.public = $NODE_PUBLIC"
echo "[lab] client.secret/.public + lab.env written to $OUT"
