#!/bin/sh
# Generates the client's ed25519 key for the V.10 lab in BOTH the form the demo wants (a raw 32-byte seed) and the
# OpenSSH authorized_keys line the server wants. Run it inside the ssh-server (or any) container so python3 is present.
#   - shared/client_ed25519_seed       : 32 raw bytes — the demo's `?key=` path (NOT an OpenSSH PEM).
#   - shared/client_authorized_key      : "ssh-ed25519 AAAA... lab-client" — copied to the server's authorized_keys.
set -e
OUT="${1:-/lab/shared}"
mkdir -p "$OUT"

python3 - "$OUT" <<'PY'
import os, sys, base64, struct, hashlib

out = sys.argv[1]

# A 32-byte ed25519 seed. Derive the public key with a pure-python ed25519 (RFC 8032) so we need no extra packages.
seed = os.urandom(32)

# --- minimal RFC 8032 ed25519 public-key derivation (clean-room, standard math) ---
p = 2**255 - 19
def inv(x): return pow(x, p-2, p)
d = (-121665 * inv(121666)) % p
I = pow(2, (p-1)//4, p)
def xrecover(y):
    xx = (y*y-1) * inv(d*y*y+1)
    x = pow(xx, (p+3)//8, p)
    if (x*x - xx) % p != 0: x = (x*I) % p
    if x % 2 != 0: x = p-x
    return x
By = (4 * inv(5)) % p
Bx = xrecover(By)
B = [Bx % p, By % p]
def edwards(P, Q):
    x1,y1 = P; x2,y2 = Q
    x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
    y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
    return [x3 % p, y3 % p]
def scalarmult(P, e):
    if e == 0: return [0,1]
    Q = scalarmult(P, e//2); Q = edwards(Q,Q)
    if e & 1: Q = edwards(Q,P)
    return Q
def encodepoint(P):
    x,y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i*8+j] << j for j in range(8)) for i in range(32))

h = hashlib.sha512(seed).digest()
a = 2**254 + sum(2**i * ((h[i//8] >> (i%8)) & 1) for i in range(3,254))
pub = encodepoint(scalarmult(B, a))

# OpenSSH public-key blob = string "ssh-ed25519" || string pub.
def ssh_string(b): return struct.pack(">I", len(b)) + b
blob = ssh_string(b"ssh-ed25519") + ssh_string(pub)
authorized = "ssh-ed25519 " + base64.b64encode(blob).decode() + " lab-client"

with open(os.path.join(out, "client_ed25519_seed"), "wb") as f: f.write(seed)
with open(os.path.join(out, "client_authorized_key"), "w") as f: f.write(authorized + "\n")
print("seed (hex):", seed.hex())
print("pub  (hex):", pub.hex())
print("authorized_key:", authorized)
PY

chmod 600 "$OUT/client_ed25519_seed"
echo "[gen] wrote $OUT/client_ed25519_seed (32-byte raw seed) + $OUT/client_authorized_key"
