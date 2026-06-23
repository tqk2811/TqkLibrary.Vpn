# lab/openconnect — VALIDATE LIVE driver V.5 OpenConnect (ocserv tự host)

Lab Docker dựng **ocserv (OpenConnect server) tự host** (ocserv 1.2.4) để **validate live** driver
`TqkLibrary.VpnClient.Drivers.OpenConnect`
([`OpenConnectConnection`](../../src/TqkLibrary.VpnClient.Drivers.OpenConnect/OpenConnectConnection.cs#L52))
interop với một server OpenConnect/Cisco-AnyConnect **thật**: HTTPS config-auth → CSTP-over-TLS data plane
(+ DTLS data path) + DPD/keepalive + rekey. Client là binary demo `.NET` self-contained chạy trong
container cùng bridge; server sinh self-signed cert + tạo user (`ocpasswd`) lúc khởi động.

Vì sao **container** (KHÔNG host-net/privileged-host) — như lab [`ikev2-native`](../ikev2-native) /
[`wireguard`](../wireguard) / [`openvpn`](../openvpn): ocserv tạo TUN **trong netns container** (chỉ cần
`/dev/net/tun` + `NET_ADMIN`), không đụng mạng VM, không cần kernel module riêng. 2 container cùng bridge
`labnet` ⇒ client gửi gói (TCP/443 CSTP + UDP/443 DTLS) tới server qua tên service. KHÔNG publish cổng:
test nội bộ bridge.

---

## 1. Topology (an toàn — như openvpn/ikev2-native)

| Container | Vai trò |
|---|---|
| `lab-oc-server` | ocserv 1.2.4, `auth=plain[ocpasswd]`, self-signed cert, `tcp-port=443` (CSTP) + `udp-port=443` (DTLS), `ipv4-network=10.70.0.0/24`, `dns=1.1.1.1`, `cisco-client-compat=true`, `dtls-legacy=true`, DPD 20s. `cap_add: NET_ADMIN` + `devices: /dev/net/tun`. rsyslog bắt session events → `/var/log/syslog`. HTTP test server `10.70.0.1:8080` (`/index.txt` nhỏ + `/big.txt` ~64KB), dnsmasq `:53` (UDP, phân giải mọi tên về GW), UDP echo `:7`. Monitor `occtl show users` + tail syslog mỗi 10s. |
| `lab-oc-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish), `sleep infinity` — chạy demo bằng `docker exec`. OpenConnect chở data trên TCP/UDP socket thường ⇒ **KHÔNG cần CAP_NET_RAW**. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host. **KHÔNG** publish cổng.

Đổi biến môi trường giữa các lần validate (ở `docker-compose.yml` hoặc inline):

| Biến | Giá trị | Ý nghĩa |
|---|---|---|
| `OC_USER` / `OC_PASS` | `testuser` / `testpass` | user ocserv (ocpasswd plain) |
| `DTLS` | `1` \| `0` | bật DTLS data path (`udp-port=443`) / TLS-only |
| `REKEY` | (rỗng) \| `<giây>` | rỗng = rekey mặc định; đặt số → `rekey-time` ngắn (test rekey V5.d), `rekey-method=new-tunnel` |

---

## 2. Build + deploy (như openvpn/wireguard)

```bash
# Trên Windows host: publish self-contained linux-x64 + copy sang VM
dotnet publish demo/Vpn2ProxyDemo/Vpn2ProxyDemo.csproj -c Release -r linux-x64 --self-contained -o <out>
scp -r <out>/* vpnlab:~/lab/openconnect/client-bin/
ssh vpnlab 'chmod +x ~/lab/openconnect/client-bin/Vpn2ProxyDemo'   # mount :ro ⇒ chmod trên host

# Trên VM: build + up
ssh vpnlab 'cd ~/lab/openconnect && docker compose up -d --build'
```

---

## 3. Chạy (`docker exec` client)

```bash
# (1) Đường TLS (CSTP) — probe ICMP + UDP DNS qua tunnel:
docker exec lab-oc-client /opt/client/Vpn2ProxyDemo dns \
    --vpn "openconnect://testuser:testpass@ocserv-server" --dns-server 10.70.0.1 --resolve example.com

# (2) Thử DTLS data path song song (V5.c) — thêm cờ --openconnect-dtls:
docker exec lab-oc-client /opt/client/Vpn2ProxyDemo dns \
    --vpn "openconnect://testuser:testpass@ocserv-server" --openconnect-dtls --dns-server 10.70.0.1 --resolve example.com

# (3) Rekey (V5.d) — restart server với REKEY ngắn rồi giữ tunnel > rekey-time:
ssh vpnlab 'cd ~/lab/openconnect && REKEY=40 docker compose up -d --force-recreate ocserv-server'
docker exec -d lab-oc-client bash -c "timeout -s INT 70 /opt/client/Vpn2ProxyDemo proxy-server \
    --vpn openconnect://testuser:testpass@ocserv-server < <(sleep 75) > /tmp/oc-proxy.log 2>&1"
# sau ~70s: grep 'rekey' /tmp/oc-proxy.log (client) + 'user logged in' /var/log/syslog (server, 2 session chồng)
```

Demo scheme `openconnect://` (alias `anyconnect://`) + cờ `--openconnect-dtls` thêm ở
[`VpnTarget`](../../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs) /
[`VpnTunnel.ConnectOpenConnectAsync`](../../demo/Vpn2ProxyDemo/VpnTunnel.cs). Cert self-signed ⇒ driver
accept-any (`serverCertificateValidation`/`dtlsCertificateValidation` trả `true`) — cookie mới authorize tunnel.

---

## 4. Quan sát server-side

```bash
docker exec lab-oc-server grep -iE "logged in|sending IPv4|DTLS|resumption|rekey|disconnect" /var/log/syslog | tail
docker exec lab-oc-server occtl -s /run/occtl.socket show users    # phiên đang sống
```

---

## 5. Kết quả validate (2026-06-24)

- **Đường TLS (CSTP) ✓ FULL tunnel:** auth cookie → CONNECT → CSTP-over-TLS, IP `10.70.0.121` + DNS 1.1.1.1
  + MTU 1372; ICMP gateway RTT 2ms + UDP DNS 2 chiều. Server `user logged in` + `rx/tx > 0` + teardown sạch.
- **Rekey (V5.d) ✓ make-before-break:** rekey `new-tunnel` → địa chỉ mới `10.70.0.195`; server thấy 2 session
  login chồng (mới TRƯỚC khi cũ disconnect).
- **DTLS (V5.c) — session_id correlation ĐÃ SỬA (lộ qua live):** trước fix client gửi ClientHello session_id
  rỗng ⇒ ocserv `invalid session ID size (0)`; sau fix (resume legacy AnyConnect: session_id + master secret
  in-band + `AllowLegacyResumption`) ⇒ ocserv `setting up legacy DTLS (resumption) connection` (session_id khớp).
  **Residual:** handshake rút gọn chưa hoàn tất với ocserv thật (`TlsFatalAlert internal_error(80)` ⇒
  `dtls_mainloop failed`) — interop DTLS legacy GnuTLS↔BouncyCastle ⇒ client **fallback CSTP-over-TLS** (đúng
  thiết kế). Chi tiết: [Transport.Dtls README](../../src/TqkLibrary.VpnClient.Transport.Dtls/README-vi.md).

> Dọn lab: `docker compose down -v`. Binary publish + cert/ocpasswd KHÔNG commit (`.gitignore`).
