#!/usr/bin/env bash
# Have the controller node also JOIN its own network as a member with a fixed overlay IP (10.144.0.1), so it exposes a
# real zt L2 interface that answers ARP/ICMP — the data-plane peer the .NET client pings. Run after setup-controller.sh.
# Usage: join-controller-as-member.sh <networkId>
set -euo pipefail

NWID=${1:?usage: join-controller-as-member.sh <networkId>}
TOKEN=$(cat /var/lib/zerotier-one/authtoken.secret)
NODE=$(cut -d: -f1 /var/lib/zerotier-one/identity.public)

zerotier-cli join "$NWID"
sleep 3
curl -s -H "X-ZT1-Auth: $TOKEN" -X POST "http://localhost:9993/controller/network/${NWID}/member/${NODE}" \
     -d '{"authorized":true,"ipAssignments":["10.144.0.1"]}' >/dev/null
sleep 5
echo "=== zt interface ==="; ip -4 addr show | grep -E "zt|10.144" || echo "(no zt address yet)"
echo "=== listnetworks ==="; zerotier-cli listnetworks
