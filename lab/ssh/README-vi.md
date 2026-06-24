# Lab V.10 — VPN-over-SSH (OpenSSH `-w` tun) live

Validate driver **VPN-over-SSH** (`Drivers.Ssh`) end-to-end với **OpenSSH server thật** (`PermitTunnel point-to-point`):
client .NET → TCP/22 → SSH-2 handshake (curve25519-sha256 KEX + ed25519 hostkey + chacha20-poly1305@openssh.com)
→ userauth (publickey ed25519 hoặc password) → channel `tun@openssh.com` point-to-point L3 → **ICMP 2 chiều**
qua overlay (client `10.10.0.2` ↔ server gateway `10.10.0.1`).

2 container trên bridge `labnet`:
- **ssh-server** (`lab-ssh:latest`, Ubuntu 24.04 + `openssh-server`): `sshd` với `PermitTunnel point-to-point`,
  user `tunuser` (mật khẩu `tunpass`) + `root` + authorized_key ed25519 của client; watcher nền dựng `tun0` =
  `10.10.0.1 peer 10.10.0.2` khi client mở channel. **Lưu ý**: OpenSSH gắn tun vào uid phiên — chỉ **root** mới
  `sys_tun_open` được trong container (`tunuser` báo `Operation not permitted`), nên đăng nhập **root** cho tun.
- **client** (`runtime-deps:8.0`): chạy demo self-contained linux-x64 qua `docker exec`.

## Chạy (trên VM `vpnlab`, không cần sudo)

```sh
# 1) publish demo linux-x64 self-contained -> ./client-bin (từ máy dev rồi scp, hoặc build sẵn)
# 2) build image + sinh khóa client + lên lab:
cd ~/ssh-lab
docker build -t lab-ssh:latest .
docker run --rm -v "$(pwd):/lab" lab-ssh:latest sh -c 'cp /lab/gen-client-key.sh /tmp/g && chmod +x /tmp/g && /tmp/g /lab/shared'
docker compose up -d

# 3) ICMP 2 chiều qua tunnel (publickey ed25519):
docker exec ssh-client sh -c 'cp /lab/shared/client_ed25519_seed /tmp/sd && chmod 600 /tmp/sd && \
  /tmp/app/Vpn2ProxyDemo dns --vpn "ssh://root@ssh-server:22?addr=10.10.0.2/30&peer=10.10.0.1&key=/tmp/sd"'
# Mong: "Gateway nội bộ: 10.10.0.1 (ICMP reachable, RTT ~Nms)".

# 4) tcpdump 2 chiều (giữ tunnel sống bằng proxy-server với stdin mở):
docker exec -d ssh-client sh -c 'cp /lab/shared/client_ed25519_seed /tmp/sd && chmod 600 /tmp/sd && \
  sleep infinity | /tmp/app/Vpn2ProxyDemo proxy-server --vpn "ssh://root@ssh-server:22?addr=10.10.0.2/30&peer=10.10.0.1&key=/tmp/sd" --proxy-port 11080'
docker exec ssh-server sh -c 'timeout 9 tcpdump -lni tun0 icmp & sleep 1; ping -c 3 10.10.0.2'
# Mong: tun0 thấy "echo request" + "echo reply" cả 2 chiều.

# 5) dọn:
docker compose down -v
```

`gen-client-key.sh` sinh `shared/client_ed25519_seed` (32 byte seed trần — `?key=` của demo) +
`shared/client_authorized_key` (dòng `ssh-ed25519 AAAA...` cho `authorized_keys` server). Khóa/binary **KHÔNG commit**
(`.gitignore`).

## Kết quả (2026-06-25, OpenSSH 9.6p1 thật)

- Handshake + KEX + NEWKEYS + cipher `chacha20-poly1305@openssh.com` ✓ (host key verify, cipher khớp byte vs sshd thật).
- **userauth publickey ed25519 ✓** (sshd `Accepted publickey for root ... ED25519`).
- channel `tun@openssh.com` point-to-point open ✓ (sau khi login root — uid 0 mới mở được tun).
- **ICMP 2 chiều ✓**: gateway probe RTT ~3ms + tcpdump tun0 `10.10.0.1 > 10.10.0.2 echo request` **và**
  `10.10.0.2 > 10.10.0.1 echo reply` cả 2 chiều.
- **1 bug interop sửa qua live** (self-pair offline không bắt): tun L3 framing trong channel-data string là
  `[uint32 address_family][ip_packet]` — **KHÔNG** có field `packet_length` dẫn đầu (phần "uint32 packet length" của
  PROTOCOL §2.3 chính là length-prefix của SSH `string`, đã bị `ReadString` ăn). Codec cũ thêm thừa 4 byte length →
  sshd đọc AF = giá trị length → misframe → gói client→server không tới tun + gói inbound decode cụt 20 byte.
