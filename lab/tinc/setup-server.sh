#!/bin/sh
# Runs INSIDE the tinc 1.1 server container. Generates Ed25519 keys for server + client, writes the meta
# config (ExperimentalProtocol = yes → SPTPS), and exports the client private key + server host file to /shared
# so the .NET harness can perform the SPTPS handshake. Then runs tincd in the foreground with debug logging.
set -e

NET=lab
CFG=/etc/tinc/$NET
SHARED=/shared
mkdir -p "$CFG/hosts" "$SHARED"

# --- server (this node) ---
cat > "$CFG/tinc.conf" <<EOF
Name = server
ExperimentalProtocol = yes
Subnet = 10.99.0.0/24
EOF

# Generate the server Ed25519 keypair non-interactively (tinc 1.1: `tinc -n NET generate-ed25519-keys`).
# This writes ed25519_key.priv and appends Ed25519PublicKey to hosts/server.
yes "" | tinc -n "$NET" generate-ed25519-keys 2>/dev/null || tinc -n "$NET" generate-ed25519-keys </dev/null 2>/dev/null || true

# Make sure the server host file has an Address and Subnet for completeness.
cat >> "$CFG/hosts/server" <<EOF
Address = $(hostname -i | awk '{print $1}')
Subnet = 10.99.0.1/32
EOF

# --- client node host entry (server must trust the client's Ed25519 pubkey) ---
# Generate a client keypair separately in a temp dir, then register its pubkey on the server.
CLIENTDIR=/tmp/clientcfg
mkdir -p "$CLIENTDIR/hosts"
cat > "$CLIENTDIR/tinc.conf" <<EOF
Name = client
ExperimentalProtocol = yes
EOF
tinc -c "$CLIENTDIR" generate-ed25519-keys </dev/null 2>/dev/null || true

# Register client's host file (pubkey + subnet) on the server so SPTPS auth can verify the client's SIG.
cp "$CLIENTDIR/hosts/client" "$CFG/hosts/client"
echo "Subnet = 10.99.0.2/32" >> "$CFG/hosts/client"

# Export to /shared for the harness:
cp "$CLIENTDIR/ed25519_key.priv" "$SHARED/client_ed25519_key.priv"
cp "$CFG/hosts/server" "$SHARED/server.host"
echo "server" > "$SHARED/server.name"

echo "=== server host file ==="
cat "$CFG/hosts/server"
echo "=== client host file (registered on server) ==="
cat "$CFG/hosts/client"
echo "=== exported to /shared ==="
ls -l "$SHARED"

# Run tincd in foreground, no detach, debug level 5 (logs handshake details), no actual tun device needed for
# the handshake test (but tincd may want one; use --no-detach and a dummy device mode).
echo "=== starting tincd (debug 5) ==="
exec tincd -n "$NET" -D -d5 --logfile=/dev/stdout
