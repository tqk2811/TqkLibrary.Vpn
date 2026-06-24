#!/bin/sh
# OpenSSH server entrypoint for the V.10 VPN-over-SSH live lab. Configures sshd with PermitTunnel point-to-point,
# installs the client's ed25519 authorized key (+ a password fallback), creates the tun device node, brings up
# tun0 with the gateway overlay IP once the client opens the tunnel channel, then runs sshd in the foreground.
set -e

GATEWAY_IP="10.10.0.1"
CLIENT_IP="10.10.0.2"

echo "[server] OpenSSH version:"
/usr/sbin/sshd -V 2>&1 | head -1 || ssh -V 2>&1 | head -1 || true

# --- tun device node (the container maps /dev/net/tun; create it if missing) ---
if [ ! -c /dev/net/tun ]; then
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200 || true
  chmod 600 /dev/net/tun || true
fi

# --- a tunnel user with a known password; root login also allowed for tun (OpenSSH ties tun to the session uid 0) ---
id tunuser >/dev/null 2>&1 || useradd -m -s /bin/bash tunuser
echo "tunuser:tunpass" | chpasswd
echo "root:rootpass" | chpasswd

# --- authorized_key for publickey auth: the lab writes the client's ed25519 public key (OpenSSH format) to
#     /lab/shared/client_authorized_key if present ---
mkdir -p /root/.ssh /home/tunuser/.ssh
if [ -f /lab/shared/client_authorized_key ]; then
  cp /lab/shared/client_authorized_key /root/.ssh/authorized_keys
  cp /lab/shared/client_authorized_key /home/tunuser/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys /home/tunuser/.ssh/authorized_keys
  chown -R tunuser:tunuser /home/tunuser/.ssh
fi

# --- sshd_config: enable PermitTunnel point-to-point + password + publickey, root login (so the tun is owned by uid 0) ---
cat > /etc/ssh/sshd_config <<EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitTunnel point-to-point
AllowTcpForwarding yes
ClientAliveInterval 30
LogLevel DEBUG3
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Generate host keys (ed25519 + rsa) if absent.
ssh-keygen -A >/dev/null 2>&1 || true
# Export the server's ed25519 host key fingerprint so the client lab can pin it (optional).
if [ -f /etc/ssh/ssh_host_ed25519_key.pub ] && [ -d /lab/shared ]; then
  cp /etc/ssh/ssh_host_ed25519_key.pub /lab/shared/server_host_ed25519_key.pub 2>/dev/null || true
fi

# --- background watcher: when sshd creates tun0 (on the client's channel open), bring it up with the gateway IP
#     and add the point-to-point peer route so ICMP replies route back over the tunnel ---
(
  while true; do
    if ip link show tun0 >/dev/null 2>&1; then
      if ! ip addr show tun0 | grep -q "$GATEWAY_IP"; then
        echo "[server] tun0 appeared — bringing it up $GATEWAY_IP peer $CLIENT_IP"
        ip addr add "$GATEWAY_IP/32" peer "$CLIENT_IP/32" dev tun0 2>/dev/null || ip addr add "$GATEWAY_IP/24" dev tun0 2>/dev/null || true
        ip link set tun0 up 2>/dev/null || true
        ip route replace "$CLIENT_IP/32" dev tun0 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
        for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done
        ip addr show tun0 || true
      fi
    fi
    sleep 1
  done
) &

echo "[server] starting sshd in the foreground (debug) on port 22 ..."
exec /usr/sbin/sshd -D -e
