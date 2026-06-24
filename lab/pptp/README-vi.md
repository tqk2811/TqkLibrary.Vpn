# lab/pptp — validate LIVE driver V.6 PPTP (RFC 2637, GRE proto-47, no-NAT)

Lab RIÊNG để validate **V.6** của driver PPTP repo TqkLibrary: control TCP/1723 +
**GRE proto-47** (raw socket) chở PPP → MS-CHAPv2 → CCP/MPPE (RC4) → IPCP.

Server = **accel-ppp** (image `lab-accel-ppp:24.04` build-from-source, có module `pptp` +
`auth_mschap_v2`, MPPE qua kernel module `ppp_mppe`). Client = binary demo `.NET`
self-contained publish (linux-x64), chạy trong container cùng bridge.

**Topology AN TOÀN (nhái [`../l2tp-nonat`](../l2tp-nonat/README-vi.md)):** 2 container trên cùng custom
bridge `labnet`, KHÔNG `network_mode: host`, KHÔNG privileged — chỉ `NET_RAW` + `NET_ADMIN`
trong netns container. Intra-bridge KHÔNG NAT ⇒ GRE proto-47 đi L2 thẳng (giống native-ESP
proto-50 P0.8c).

---

## ⚑ Kết quả validate LIVE (2026-06-24)

**Client PPTP CHỨNG MINH ĐÚNG tới tầng MPPE — khớp byte-for-byte với reference `pppd`.** Đã chạy
thật lab này; quan sát qua tcpdump GRE + accel-ppp log + giải mã MPPE bằng reference Python:

| Tầng | Trạng thái | Bằng chứng |
|------|-----------|-----------|
| **Control TCP/1723** | ✅ | SCCRQ/SCCRP + OCRQ/OCRP → Call-IDs (client `call 16384`=0x4000, server `call N`) |
| **GRE-47 data plane** | ✅ | 2 chiều, seq tăng + ack piggyback (RFC 2637 §4.4); intra-bridge no-NAT |
| **LCP** | ✅ | server `recv [LCP ConfReq … magic 5b3c2a1d]` + ConfAck 2 chiều (sau khi sửa **bug double-FF03**) |
| **MS-CHAPv2 auth** | ✅ | server `vpn: authentication succeeded` + `S=…M=Authentication succeeded` |
| **CCP/MPPE negotiate** | ✅ | stateless 128-bit (`+H +S`), 2 chiều acked, `ccp_layer_started` |
| **MPPE encrypt** | ✅ **byte-perfect** | gói mã hóa đầu (`00fd 9000 63a4…`) **giải mã ra IPCP hợp lệ** `8021 0101 0010 0306…` (proven bằng reference Python decrypt với key thứ-2; khớp thuật toán kernel `ppp_mppe.c`) |
| **IPCP** | ⛔ **blocked server-side** | server accel-ppp **không mở IPCP** (`IPCP: discarding packet`, không bao giờ `send [IPCP ConfReq]`) — **reference `pppd` client FAIL Y HỆT** ⇒ blocker là server, KHÔNG phải client |

### 3 BUG client phát hiện + sửa qua live (offline self-pair KHÔNG bắt)

1. **GRE double-FF03** — [`PptpGreChannel.PrependAddressControl`](../../src/TqkLibrary.VpnClient.Pptp/Gre/PptpGreChannel.cs):
   PAC thật (kernel `pptp`/accel-ppp) GIỮ HDLC `FF 03` TRONG payload GRE (trái RFC 2637 §4.3),
   ta prepend thêm `FF 03` nữa ⇒ `FF 03 FF 03 C0 21…` ⇒ PPP engine đọc proto = `0xFF03`,
   không dispatch LCP ⇒ kẹt LCP. Sửa = prepend **idempotent** (chỉ thêm nếu chưa có).
2. **MPPE stateless first-packet rekey** — [`MppeSession`](../../src/TqkLibrary.VpnClient.Crypto/Mppe/MppeSession.cs):
   stateless mode (RFC 3078 §4.1) phải rekey TRƯỚC MỌI gói KỂ CẢ gói đầu — kernel `mppe_init`
   = `mppe_rekey(1)` (key khởi tạo) rồi mỗi `mppe_compress` = `mppe_rekey(0)`. Ta bỏ rekey gói đầu
   ⇒ key lệch 1 bước ⇒ server giải mã ra rác ⇒ `ProtoRej` protocol ngẫu nhiên. Sửa = rekey mọi gói.
3. **IPCP-trước-CCP cleartext** — [`PppEngine`](../../src/TqkLibrary.VpnClient.Ppp/PppEngine.cs) `deferNetworkLayer`:
   engine khởi IPCP ngay sau auth, TRƯỚC khi CCP/MPPE mở ⇒ gói IPCP ConfReq đầu đi **cleartext** (proto
   0x8021) ⇒ server `ProtoRej <8021>` + làm lệch trạng thái MPPE server. Sửa = hoãn network layer
   tới khi `CcpOpened` (gói IPCP đầu đã mã hóa). (`reference pppd` cũng gửi IPCP đầu cleartext, rồi
   encrypted — server reject cả hai.)

### ⛔ Blocker server-side (KHÔNG phải client) — accel-ppp PPTP không mở IPCP

accel-ppp (build trong image này, MPPE qua kernel `ppp_mppe`) **không bao giờ gửi `IPCP ConfReq`** và
`discard` IPCP của client (`fsm_state == FSM_Closed`), với MỌI biến thể config thử qua
(`mppe=require`/`prefer`, IP tĩnh chap-secrets, `[ip-pool]` 99 IP free, `[client-ip-range]`
disable/subnet). **Reference Linux `pptp`+`pppd` client (cài `pptp-linux`) FAIL Y HỆT** trên cùng
server ⇒ chứng minh dứt khoát blocker là **server accel-ppp PPTP + IPCP trong môi trường Docker/kernel
này**, KHÔNG phải driver TqkLibrary. (poptop `pptpd` không có trong Ubuntu 24.04 repo ⇒ không dựng được
nhanh để đối chứng; SSTP/L2TP của cùng accel-ppp build IPCP chạy OK — nhánh ctrl PPTP khác.)

---

## Cách chạy (runbook)

```bash
# Trên Windows host: publish self-contained + scp sang VM (xem fvq-overnight-progress §V.6)
dotnet publish demo/Vpn2ProxyDemo -c Release -r linux-x64 --self-contained -o <out>
# tar <out> → scp vpnlab:~/lab/pptp/ → giải nén vào ./client-bin

# Trên VM: tạo chap-secrets (gitignored): echo "vpn  *  vpn  *" > ~/lab/pptp/chap-secrets
cd ~/lab/pptp && docker compose up -d
docker exec lab-pptp-client /opt/client/Vpn2ProxyDemo dns --vpn 'pptp://vpn:vpn@pptp-server'
# Quan sát: docker exec lab-pptp-server tail -f /var/log/accel-ppp/accel-ppp.log
#           docker exec lab-pptp-server accel-cmd -p 2000 show sessions
docker compose down -v   # dọn
```

Demo cần `cap_add: NET_RAW` (đã đặt trong compose) để mở raw socket proto-47.
