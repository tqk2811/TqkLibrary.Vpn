# Lab V.11 — vtun full-tunnel live (vtund 3.0.4 THẬT)

Kiểm chứng **driver `Drivers.Vtun`** end-to-end với **vtund 3.0.4** (apt `vtun`) THẬT: client .NET bắt tay
challenge-response (MD5 + Blowfish-ECB) → data plane length-prefix → **ICMP 2 chiều** qua tunnel.

## Thành phần
- [`Dockerfile`](Dockerfile) — image `lab-vtun` = Ubuntu 24.04 + `apt install vtun` (vtund 3.0.4-2ubuntu3) + tcpdump/iproute2.
- [`vtund.conf`](vtund.conf) — 3 host:
  - `test`: `passwd pass`, `type tun`, `proto tcp`, `encrypt no`, `compress no`, tunnel `10.11.0.1` ↔ `10.11.0.2`.
  - `enc`: như trên nhưng `encrypt blowfish128ecb` (cipher mặc định, gửi cho client = flag `E1`), tunnel `10.12.0.1` ↔ `10.12.0.2`.
  - `tapsrv`: `type ether` (tap/L2), `proto tcp`, server gán `10.13.0.1/24` lên `tapNN`; client (static `10.13.0.2` trên VtunEthernetChannel+VirtualHost) ARP-resolve rồi ping qua segment L2.
- [`openssl-legacy.cnf`](openssl-legacy.cnf) — bật **legacy provider** của OpenSSL 3.0. **BẮT BUỘC cho host `enc`** trên
  Ubuntu 24.04: Blowfish dời sang legacy provider ở OpenSSL 3.0 và KHÔNG nạp mặc định → vtund 3.0.4 gọi `EVP_bf_ecb()`
  fail → session đóng ngay. Chạy vtund với `OPENSSL_CONF=/tmp/openssl-legacy.cnf` để host `enc` lên được.
- [`setup-server.sh`](setup-server.sh) — entrypoint: tạo `/dev/net/tun`, bật ip_forward, chạy `vtund -s -n -f ... -P 5000`
  (server foreground).
- [`docker-compose.yml`](docker-compose.yml) — 2 container trên bridge `labnet`: `vtun-server` (image lab-vtun) +
  `client` (runtime-deps, sleep infinity để `docker exec` harness).
- `harness/` — runner .NET (KHÔNG trong solution): publish self-contained linux-x64, chạy `VtunConnection` thật +
  `TcpIpStack`, ping server qua tunnel. Args: `<serverHost> <port> <hostName> <password> <tunnelAddr/cidr> <peerAddr>`.

## Chạy (trên VM `ssh vpnlab`, thư mục `~/vtun-lab/`)
```sh
# 1) publish harness (trên máy dev) → scp vào ~/vtun-lab/client-bin/
dotnet publish lab/vtun/harness -c Release -r linux-x64 -o publish
scp -r lab/vtun/{Dockerfile,vtund.conf,setup-server.sh,docker-compose.yml} vpnlab:~/vtun-lab/
scp -r lab/vtun/harness/publish/* vpnlab:~/vtun-lab/client-bin/

# 2) build image + lên lab
docker build -t lab-vtun:latest .
docker compose up -d

# 3) chạy client harness (no-encrypt host 'test')
docker exec vtun-client sh -c 'cp -r /app /tmp/app && chmod +x /tmp/app/harness && \
  /tmp/app/harness vtun-server 5000 test pass 10.11.0.2/24 10.11.0.1'

# 3b) encrypt host 'enc' (Blowfish-128-ECB) — cần legacy provider; chạy 1 vtund phụ với OPENSSL_CONF
docker exec vtun-server sh -c 'cp /lab/openssl-legacy.cnf /tmp/ && \
  OPENSSL_CONF=/tmp/openssl-legacy.cnf vtund -s -n -f /etc/vtund.conf -P 5002 2>/tmp/vtund-leg.err &'
docker exec vtun-client sh -c '/tmp/app/harness vtun-server 5002 enc pass 10.12.0.2/24 10.12.0.1'

# 3c) tap host 'tapsrv' (type ether / L2) — harness dùng cùng facade (VirtualHost L3), overlay 10.13.0.2
docker exec vtun-client sh -c '/tmp/app/harness vtun-server 5000 tapsrv pass 10.13.0.2/24 10.13.0.1'

# 4) dọn
docker compose down -v
```

## Kết quả VALIDATE LIVE ✓ (2026-06-24)
Client log:
```
[vtun] handshake: authenticated; server flags = Tcp, KeepAlive, Tun
[+] tunnel up. server flags = Tcp, KeepAlive, Tun, tunnel IP = 10.11.0.2/24, peer = 10.11.0.1, mtu = 1450
[ping 1] reply from 10.11.0.1: 38.7 ms ; [ping 2..4] ~0.4 ms
[✓✓] FULL-TUNNEL LIVE OK — 4/4 ICMP echo replies through vtund (2-way ICMP confirmed)
```
Server log (vtund `-n` debug):
```
authentication[18]: Use SSL-aware challenge/response        # đúng nhánh Blowfish/MD5 (HAVE_SSL)
authentication[18]: Session test[172.19.0.3:53868] opened   # auth OK, session mở
test tun tun0[18]                                            # tun device tạo + bind (data plane lên)
test closing[18]: Session test closed                       # CONN_CLOSE teardown nhận đúng
```
**Reject path live ✓**: sai password → server `Denied connection from ...` → client `VpnAuthenticationException (got 'ERR')`.

**Wire (tcpdump eth0 tcp/5000)**: histogram độ dài segment = `50` (×6, khối auth 50-byte NUL-pad: greeting/HOST/CHAL/
response/FLAGS), `62` (data frame = 2-byte length header + 60-byte ICMP/IP), `2` (×4, control frame ECHO_REQ/ECHO_REP
0-payload). Khớp byte-for-byte spec vtun 3.0.x.

**0 BUG** — golden vector OpenSSL (`MD5("pass")` → `BF-ECB` → `7416f64c…`) khóa offline trước nên challenge-response
đúng ngay lần đầu live.

## Kết quả VALIDATE LIVE — DATA-PLANE ENCRYPT ✓ (2026-06-25)
Host `enc` (`encrypt blowfish128ecb`), vtund chạy với `OPENSSL_CONF=openssl-legacy.cnf`:
```
[vtun] handshake: authenticated; server flags = Encrypt, Tcp, KeepAlive, Tun
[vtun] handshake: data-plane encryption enabled: Blowfish128Ecb
[+] tunnel up. ... tunnel IP = 10.12.0.2/24, peer = 10.12.0.1
[ping 1] reply 37ms ; [ping 2..4] ~1ms
[✓✓] FULL-TUNNEL LIVE OK — 4/4 ICMP echo replies (2-way ICMP confirmed)
```
Server log: `enc tun tun0: Blowfish-128-ECB encryption initialized` (khớp client cipher byte-exact).

**Wire (tcpdump tcp/5002)**: histogram = `50`×5 (auth blocks, flags `<TuKE1>`), **`66`×N (data frame = 2-byte header +
64-byte CIPHERTEXT** cho gói ICMP 60-byte pad lên 64 = bội số 8), `2`×2 (control). `tcpdump -A` tìm chuỗi `ICMP/echo` =
**0 match**; đếm `0040 4500` (header IP plaintext bên trong data frame) = **0** → payload mã hóa hoàn toàn, không lộ
plaintext trên dây. Padding khớp codec: 60 → pad 4 → 64.

**1 blocker môi trường (không phải bug client)**: OpenSSL 3.0.13 (Ubuntu 24.04) ẩn Blowfish trong legacy provider không nạp
mặc định → vtund 3.0.4 gọi `EVP_bf_ecb()` fail → session `enc` đóng ngay (không có dòng `tun tun0`/`encryption
initialized`). Fix = `OPENSSL_CONF=openssl-legacy.cnf` (bật legacy). Sau đó ICMP 2 chiều ngay.

## Kết quả VALIDATE LIVE — TAP (type ether / L2) ✓ (2026-06-25)
Host `tapsrv` (`type ether`), client dựng `VtunEthernetChannel` + `ArpResolver` + `VirtualHost` (tái dùng Ethernet fabric):
```
[vtun] handshake: authenticated; server flags = Tcp, KeepAlive, Ether
[+] tunnel up. server flags = Tcp, KeepAlive, Ether, tunnel IP = 10.13.0.2/24, peer = 10.13.0.1, mtu = 1436
[ping 1] reply 42ms ; [ping 2..4] ~0.7ms
[✓✓] FULL-TUNNEL LIVE OK — 4/4 ICMP echo replies (2-way ICMP confirmed)
```
Server log: `tapsrv ether tap0` (tap device bound). **MTU 1436 = 1450 − 14** (VirtualHost trừ header Ethernet → stack
clamp MSS). **Wire (tcpdump tcp/5000)**: data frame `length 76` = 2-byte header + **74-byte Ethernet frame** (14 header +
60 ICMP/IP) — so với tun `length 62` (không header Ethernet) thì +14 đúng; **2 frame ARP (ethertype 0806)** trong stream →
client ARP-resolve MAC của `10.13.0.1` qua segment L2 (bridge hoạt động đúng). **0 bug.**

## Ghi chú bảo mật
⚠️ vtun auth/data crypto **legacy yếu** (Blowfish-ECB/MD5-challenge; `encrypt no` ⇒ data plane cleartext; `encrypt yes` ⇒
Blowfish-128-**ECB** — không chaining/IV/auth, lộ cấu trúc plaintext, malleable). Lab interop only — KHÔNG dùng vtun cho
production.
