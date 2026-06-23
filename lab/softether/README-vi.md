# lab/softether — VALIDATE LIVE driver V.4 SoftEther (SoftEther VPN Server tự host)

Lab Docker dựng **SoftEther VPN Server tự host** (image `siomiz/softethervpn`, SoftEther 4.43 Build 9799) để
**validate live** driver `TqkLibrary.VpnClient.Drivers.SoftEther`
([`SoftEtherConnection`](../../src/TqkLibrary.VpnClient.Drivers.SoftEther/SoftEtherConnection.cs#L41))
interop với một server SoftEther **thật**: watermark POST → hello → login (SHA-0 secure_password) → welcome →
data plane Ethernet-over-TLS, SecureNAT cấp IP qua DHCP, ARP/VirtualHost + keep-alive. Client là binary demo
`.NET` self-contained chạy trong container cùng bridge; server tự sinh self-signed cert + tạo user lúc khởi động.

Vì sao **container** (KHÔNG host-net/privileged-host) — như lab [`ikev2-native`](../ikev2-native) /
[`wireguard`](../wireguard) / [`openvpn`](../openvpn) / [`openconnect`](../openconnect): SecureNAT chạy
**user-mode** (image ép `DisableKernelModeSecureNAT`/`DisableIpRawModeSecureNAT`), chỉ cần `/dev/net/tun` +
`NET_ADMIN`, không đụng mạng VM. 2 container cùng bridge `labnet` ⇒ client mở TLS/443 tới server qua tên
service. KHÔNG publish cổng: test nội bộ bridge.

---

## Watermark GPL — rủi ro đã GỠ (không cần blob ảnh GPL)

SoftEther server kiểm watermark POST trong `ServerDownloadSignature` (Cedar `Protocol.c`): body POST hợp lệ khi
**hoặc** khớp byte-exact ảnh GPL `WaterMark[]` (GIF, ~4 KB — KHÔNG commit), **hoặc** bằng đúng hằng giao thức
`HTTP_VPN_TARGET_POSTDATA = "VPNCONNECT"` (10 byte ASCII, Mayaqua `Network.h`). Đường thứ hai là **chính thức
trong server** và `"VPNCONNECT"` là một protocol constant (không phải tác phẩm có watermark bản quyền), nên lab
dùng nó: tạo file `watermark.bin = "VPNCONNECT"` rồi truyền `--watermark`. Đã xác nhận live: body `"VPNCONNECT"`
→ HTTP 200; body placeholder → HTTP 403.

```bash
printf 'VPNCONNECT' > ~/lab/softether/client-bin/watermark.bin   # 10 byte, KHÔNG commit (xem .gitignore)
```

---

## 1. Topology (an toàn — như openconnect/openvpn)

| Container | Vai trò |
|---|---|
| `lab-se-server` | `siomiz/softethervpn` — Hub `DEFAULT`, **SecureNAT** (DHCP `192.168.30.0/24` GW `192.168.30.1` + NAT user-mode), 1 user password-auth (env `USERNAME`/`PASSWORD`, SHA-0), SSL-VPN `443/tcp`, self-signed cert. `cap_add: NET_ADMIN` + `devices: /dev/net/tun`. Log: `/usr/vpnserver/server_log/vpn_*.log` (session create/auth/DHCP/terminate + byte stats). |
| `lab-se-client` | `runtime-deps:8.0`, mount `./client-bin` (binary publish + `watermark.bin`), `sleep infinity` — chạy demo bằng `docker exec`. SoftEther chở data Ethernet-over-TLS trên TCP socket thường ⇒ **KHÔNG cần CAP_NET_RAW**. |

An toàn: **KHÔNG** `network_mode: host`, **KHÔNG** privileged-host. **KHÔNG** publish cổng.

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `SE_USER` / `SE_PASS` | `vpn` / `vpn` | user password-auth (client gửi `secure_password = SHA0(SHA0(pass‖UPPER(user))‖random)`) |

---

## 2. Build + deploy (như openvpn/openconnect)

```bash
# Trên Windows host: publish self-contained linux-x64 + copy sang VM
dotnet publish demo/Vpn2ProxyDemo/Vpn2ProxyDemo.csproj -c Release -r linux-x64 --self-contained -o <out>
scp -r <out>/* vpnlab:~/lab/softether/client-bin/
ssh vpnlab 'chmod +x ~/lab/softether/client-bin/Vpn2ProxyDemo'           # mount :ro ⇒ chmod trên host
ssh vpnlab "printf 'VPNCONNECT' > ~/lab/softether/client-bin/watermark.bin"

# Trên VM: up server (image pull sẵn) + client
ssh vpnlab 'cd ~/lab/softether && SE_USER=vpn SE_PASS=vpn docker compose up -d'
```

---

## 3. Chạy (runbook)

```bash
# Probe UDP + DNS-over-UDP qua tunnel (kiểm data plane 2 chiều)
ssh vpnlab 'docker exec lab-se-client /opt/client/Vpn2ProxyDemo dns \
  --vpn "ssl://vpn:vpn@softether-server?hub=DEFAULT" --watermark /opt/client/watermark.bin'

# Server log (session/auth/DHCP/byte stats)
ssh vpnlab 'docker exec lab-se-server tail -20 /usr/vpnserver/server_log/vpn_$(date +%Y%m%d).log'
```

`--vpn ssl://user:pass@host?hub=<Hub>` — scheme `ssl` (alias SoftEther), `?hub=` mặc định `VPNGATE` (lab dùng
`DEFAULT`). `--watermark <file>` trỏ tới `watermark.bin`.

---

## 4. Kết quả validate (live — server tự host)

**Đường SSL-VPN full tunnel ✓ (end-to-end):**
- Watermark `"VPNCONNECT"` → HTTP 200 (qua check 403). Hello → login → **welcome accepted** (server log
  `Successfully authenticated as user "vpn"` + `Use of encryption: Yes`).
- **DHCP lease từ SecureNAT**: IP `192.168.30.1x`, DNS `192.168.30.1`, MTU 1486 (server log
  `SID-SECURENAT-1 ... DHCP server ... allocated ... new IP address 192.168.30.10`).
- L2↔L3 bridge bound (ARP/VirtualHost). **ICMP gateway `192.168.30.1` RTT 1 ms** (2 chiều). **UDP DNS qua
  tunnel**: phân giải `google.com` (SecureNAT egress). Server byte stats 2 chiều `> 0` (vd outgoing 2811 /
  incoming 2706 bytes). Keep-alive block (`KEEP_ALIVE_MAGIC`) giữ session, teardown sạch.

**Bug interop đã sửa (phát hiện qua live, offline self-pair không bắt):** xem
[README driver §trạng thái](../../src/TqkLibrary.VpnClient.Drivers.SoftEther/README-vi.md) — gồm: HTTP-PACK
framing (bỏ length-prefix thừa), field session key (`session_key` DATA, `session_key_32` INT, không phải
`session_name`), data-plane **SSL-data** (`use_encrypt` ⇒ giữ trong SSL; mặc định bật — `use_encrypt=off`
SoftEther rớt xuống raw-TCP mà byte-stream transport không biểu diễn được), keep-alive block magic
`0xFFFFFFFF`, re-inject leftover handshake→data.

**Residual (không chặn driver):** TCP-tới-internet qua SecureNAT chưa kiểm (lab bridge isolated + dính
residual shared-IpStack TCP send-window như V.2). UDP/ICMP 2 chiều đã chứng minh data plane.

---

## 5. Dọn lab

```bash
ssh vpnlab 'cd ~/lab/softether && docker compose down -v'
```
