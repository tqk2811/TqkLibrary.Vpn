#!/bin/sh
# Runs INSIDE the tinc 1.1 server container for the FULL-TUNNEL lab (V.7.2 phase b). Generates the server Ed25519
# keypair, writes a router-mode meta config with a Subnet, brings up a tun device (10.99.0.1) via tinc-up, bakes the
# client's pre-generated Ed25519 public key into hosts/client, and runs tincd in the foreground with debug logging.
# The .NET client (driver Drivers.Tinc) then handshakes over TCP, exchanges a data-plane key, and pings 10.99.0.1.
set -e

NET=lab
CFG=/usr/local/etc/tinc/$NET
SHARED=/shared
mkdir -p "$CFG/hosts" "$SHARED"

# --- server meta config: router mode, our overlay subnet ---
cat > "$CFG/tinc.conf" <<EOF
Name = server
ExperimentalProtocol = yes
Mode = router
Subnet = 10.99.0.1/32
EOF

# tinc-up brings the tun up with the server's overlay /32 and an explicit host route to the client overlay, so the
# kernel sends packets for 10.99.0.2 out the tun (where tincd reads them and forwards to the client over the tunnel)
# instead of treating the /24 as on-link and trying neighbour resolution on a NOARP device.
cat > "$CFG/tinc-up" <<'EOF'
#!/bin/sh
ip link set $INTERFACE up
ip addr add 10.99.0.1/32 dev $INTERFACE
ip route add 10.99.0.2/32 dev $INTERFACE 2>/dev/null || true
EOF
chmod +x "$CFG/tinc-up"

cat > "$CFG/tinc-down" <<'EOF'
#!/bin/sh
ip route del 10.99.0.2/32 dev $INTERFACE 2>/dev/null || true
ip addr del 10.99.0.1/32 dev $INTERFACE 2>/dev/null || true
ip link set $INTERFACE down 2>/dev/null || true
EOF
chmod +x "$CFG/tinc-down"

# Generate the server Ed25519 keypair non-interactively (writes ed25519_key.priv + appends Ed25519PublicKey to hosts/server).
yes "" | tinc -n "$NET" generate-ed25519-keys 2>/dev/null || tinc -n "$NET" generate-ed25519-keys </dev/null 2>/dev/null || true

# Server host file: address + its overlay subnet.
cat >> "$CFG/hosts/server" <<EOF
Address = $(hostname -i | awk '{print $1}')
Subnet = 10.99.0.1/32
EOF

# --- client node host entry: trust the client's pre-generated Ed25519 pubkey + its overlay subnet ---
cat > "$CFG/hosts/client" <<EOF
Subnet = 10.99.0.2/32
EOF
if [ -f "$SHARED/client.pub" ]; then
	echo "Ed25519PublicKey = $(cat "$SHARED/client.pub")" >> "$CFG/hosts/client"
	echo "=== baked client Ed25519PublicKey into hosts/client before tincd start ==="
else
	echo "=== WARNING: /shared/client.pub absent; run 'harness gen-key' before starting the server ==="
fi

# Export the server host file (Address/Ed25519PublicKey/Subnet) for the .NET client's peerhost=.
cp "$CFG/hosts/server" "$SHARED/server.host"
echo "server" > "$SHARED/server.name"

echo "=== server host file ==="; cat "$CFG/hosts/server"
echo "=== client host file ==="; cat "$CFG/hosts/client"
echo "=== starting tincd (router mode, tun up, debug 5) ==="
exec tincd -n "$NET" -D -d5 --logfile=/dev/stdout
