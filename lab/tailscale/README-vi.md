# Lab Tailscale (V.7.5) — control plane ts2021 vs Headscale + data plane WireGuard

Lab kiểm thử **live** driver Tailscale: control plane **ts2021** (Noise IK + đăng nhập Headscale bằng preauth
key + register node + netmap) ghép vào **data plane WireGuard tái dùng nguyên** (V.3). Control server là
**Headscale** (open-source self-host, image `headscale/headscale`).

## Topology (`docker-compose.yml`, bridge `tsnet` 172.30.0.0/24)

| Container | IP bridge | Vai trò |
|-----------|-----------|---------|
| `ts-headscale` | 172.30.0.2 | Headscale (control server ts2021 + netmap) |
| `ts-peer` | 172.30.0.3 | node `tailscale` THẬT (peer, overlay `100.64.0.1`) — cần disco |
| `ts-client` | 172.30.0.10 | client .NET (demo) — overlay do Headscale cấp |
| `ts-client2` | 172.30.0.11 | client .NET thứ 2 (dùng khi test 2 client .NET) |

## Chạy

```bash
# 1. Headscale lên + tạo user + preauth keys
docker compose up -d headscale
docker exec ts-headscale headscale users create labuser
docker exec ts-headscale headscale preauthkeys create --user 1 --reusable --expiration 24h   # client authkey

# 2. (tuỳ chọn) node tailscale thật làm peer
TS_PEER_AUTHKEY=<peer authkey> docker compose up -d ts-peer

# 3. publish demo self-contained linux-x64 -> scp -> giải nén vào /app của container client
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained -o publish
#    copy vào ts-client:/app, viết /lab/client.tailscale (xem dưới)

# 4. chạy client .NET
docker exec ts-client sh -c 'cd /app && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 ./Vpn2ProxyDemo dns --vpn /lab/client.tailscale'
```

### File `client.tailscale` (ini)

```ini
server=http://172.30.0.2:8080
authkey=<preauth key>
mtu=1280
# (tuỳ chọn) quảng bá endpoint WG của chính mình để peer trả lời handshake (disco stand-in tối giản):
wgport=41641
endpoint=172.30.0.10:41641
# (tuỳ chọn) keys X25519 cố định (64-hex) để re-run cùng 1 node, không sinh node mới mỗi lần:
machinekey=<64 hex>
nodekey=<64 hex>
```

## Trạng thái validate (2026-06-24)

**Control plane ts2021 — VALIDATE LIVE FULL ✓** vs Headscale v0.29.1:
- `GET /key?v=113` → 200 (lấy machine pubkey `mkey:` của control).
- `POST /ts2021` → **101 Switching Protocols** (Noise IK `Noise_IK_25519_ChaChaPoly_BLAKE2s` được Headscale chấp nhận;
  HTTP/2 h2c chạy trong kênh Noise qua `SocketsHttpHandler.ConnectCallback` + `Http2UnencryptedSupport`).
- `POST /machine/register` → 200, **`MachineAuthorized`** (preauth key trong `Auth.AuthKey`).
- `POST /machine/map` (Stream=true long-poll, đọc khung `[len LE u32][JSON]`) → **netmap** (self Node + Peers[]).
- 2 node .NET đăng ký thật: `tqk-client1` = `100.64.0.19`, `tqk-client2` = `100.64.0.20` (`headscale nodes list`).
- `NetmapToWireGuardConfig`: self `Addresses` → tun IP, peer `Key` (nodekey) → WG pubkey, `AllowedIPs` → allowed-ips,
  `Endpoints` → endpoint.

**Data plane WireGuard — initiation 2 chiều ✓, completion blocked (đúng giới hạn đã biết):**
- Client gửi **WireGuard handshake initiation type-1 (148 byte)** tới endpoint peer lấy từ netmap; tcpdump xác nhận
  gói đi tới đúng `172.30.0.x:41641`; ARP resolve OK.
- Quảng bá `endpoint=172.30.0.x:41641` trong MapRequest → peer **thấy endpoint của client trong netmap của nó**.
- Giữa **2 client .NET**: initiation type-1 chảy **2 CHIỀU** (`172.30.0.10 ↔ 172.30.0.11`, 148B mỗi hướng).
- **Không hoàn tất handshake** vì:
  1. `WireGuardConnection` là **initiator-only** (không đáp type-1 của peer — vai trò responder chỉ có trong test),
     nên 2 client .NET đều initiate, không bên nào trả type-2.
  2. node `tailscale` THẬT bọc WireGuard trong **disco** (magicsock): nó cần disco ping/pong validate path trước khi
     trả handshake; raw-WireGuard không qua disco bị magicsock bỏ qua.

**Còn lại (future, ngoài phạm vi V.7.5 đợt này):**
- **disco** (Curve25519-boxed ping/pong, NAT path discovery) để interop data-plane với node tailscale thật.
- **DERP relay** (WebSocket/HTTPS relay khi không P2P được).
- WireGuard **responder role** trong client (để 2 client .NET tự handshake nhau) HOẶC peer là plain wireguard-go.

## Dọn

```bash
docker compose down -v
docker rm -f ts-client2 2>/dev/null
```
