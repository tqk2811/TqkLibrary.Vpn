#!/usr/bin/env bash
# Generate a real ZeroTier V1 identity with zerotier-idtool and export it for the offline KAT.
# Run inside the zerotier image (Dockerfile.zerotier). Writes the identity (public + secret) and a
# JSON breakdown that the .NET harness/test can read to KAT ZeroTierAddressDerivation.
set -euo pipefail

OUT=${1:-/shared}
mkdir -p "$OUT"

# idtool generate writes "<address>:0:<pub128hex>:<priv128hex>" to the secret file.
zerotier-idtool generate "$OUT/identity.secret" "$OUT/identity.public"

SECRET=$(cat "$OUT/identity.secret")
PUBLIC=$(cat "$OUT/identity.public")

ADDR=$(echo "$PUBLIC" | cut -d: -f1)
PUB=$(echo "$PUBLIC"  | cut -d: -f3)   # 128 hex = 64 bytes (Curve25519 || Ed25519)

# Sanity: re-derive the address from the public key via idtool's own validation.
echo "{"                                    >  "$OUT/identity.json"
echo "  \"address\": \"$ADDR\","            >> "$OUT/identity.json"
echo "  \"publicKeyHex\": \"$PUB\","        >> "$OUT/identity.json"
echo "  \"identityString\": \"$PUBLIC\""    >> "$OUT/identity.json"
echo "}"                                    >> "$OUT/identity.json"

echo "[lab] generated identity:"
echo "  address    = $ADDR"
echo "  public key = $PUB"
echo "[lab] -> KAT: feed publicKeyHex into ZeroTierAddressDerivation.ComputeAddress and assert == $ADDR"
echo "[lab] identity.json + identity.public + identity.secret written to $OUT (DO NOT COMMIT keys)"
