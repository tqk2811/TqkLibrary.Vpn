# lab/nebula — validate LIVE handshake V.7.1 Nebula (Noise IX, interop binary thật)

Lab kiểm chứng **protocol layer V.7.1** (project [`TqkLibrary.VpnClient.Nebula`](../../src/TqkLibrary.VpnClient.Nebula)) bằng cách
bắt tay **Noise IX** với binary **`nebula` THẬT** (Slack, github.com/slackhq/nebula) — bắt bug interop mà self-pair
offline không thấy (bài học WireGuard construction-string / IKEv2 MSK).

Khác các lab trước (publish→scp→docker exec, 2 container bridge): Nebula handshake-interop chạy **đơn giản** —
1 process `nebula` làm responder/lighthouse + 1 harness `.NET` làm initiator, cùng host (host network).

---

## ⚑ Kết quả validate LIVE (2026-06-24, nebula v1.9.5)

**Handshake Noise IX interop HOÀN TOÀN THÀNH CÔNG — nebula THẬT chấp nhận + trả lời, ta giải mã + verify cert.**

| Tầng | Trạng thái | Bằng chứng |
|------|-----------|-----------|
| **Cert codec offline** | ✅ byte-perfect | parse `ca.crt`/`client.crt` thật; **re-marshal details == signed bytes (100==100)**; fingerprint khớp `nebula-cert print` (`03a4fc…`) |
| **Ed25519 verify** | ✅ | CA self-sign valid + client cert sig valid against CA pubkey (`846427…`) |
| **X25519 key ↔ cert** | ✅ | private key (`NEBULA X25519 PRIVATE KEY`) derive ra đúng pubkey trong cert |
| **Handshake stage 1 (ta→nebula)** | ✅ | nebula log `Handshake message received certName=client … style:ix_psk0 vpnIp=192.168.100.5` — **KHÔNG** `invalid`/`failed to decrypt` |
| **Handshake stage 2 (nebula→ta)** | ✅ | nebula `Handshake message sent stage:2`; harness **giải mã thành công** (`ConsumeResponse` OK) |
| **Responder cert verify** | ✅ | recombine static pubkey (Noise `s` token) → verify Ed25519 against CA → `name='lighthouse'` valid |
| **Transport keys** | ✅ | Split crossed keys; `ResponderIndex` harness decode == `responderIndex` trong log nebula |
| **Data plane (ICMP, stretch)** | ⏳ tunnel-lifecycle | gói data AEAD gửi đi; nebula trả `RecvError` (tunnel half-open bị tear-down vì harness 1-shot exit) — **KHÔNG** lỗi decrypt/spoof trong log ⇒ crypto đúng, còn lại là việc của driver phase (b) |

**Chứng minh dứt khoát**: mọi byte của Noise IX khớp nebula — construction string `Noise_IX_25519_AESGCM_SHA256`,
prologue rỗng (MixHash empty), thứ tự token (`e,s` plaintext msg1 / `e,ee,se,s,es` AEAD msg2), thứ tự DH ee/se/es,
payload protobuf `NebulaHandshake`, cert strip-pubkey + recombine. **First-run success, KHÔNG có bug interop phải sửa**
(nhờ verify spec wire-format kỹ trước + cert codec đã đối chiếu cert thật offline trước khi mở socket).

---

## Chạy lại

Trên VM lab (`ssh vpnlab`, Docker + internet), thư mục `~/nebula-lab/`:

```bash
# 1. Tải nebula + nebula-cert (binary Go tĩnh, KHÔNG cần Go toolchain)
VER=v1.9.5
curl -sSL -o nebula.tar.gz \
  "https://github.com/slackhq/nebula/releases/download/${VER}/nebula-linux-amd64.tar.gz"
tar xzf nebula.tar.gz   # → ./nebula ./nebula-cert

# 2. Sinh CA + cert (xem gen-certs.sh)
NEBULA_CERT=./nebula-cert bash gen-certs.sh

# 3. Chạy nebula responder (Docker host-network, tun disabled ⇒ không cần root tun)
docker run -d --name nebula-responder --network host -v ~/nebula-lab:/lab:ro -w /lab \
  alpine:3.20 sh -c "cp /lab/responder.yml /tmp/r.yml; exec /lab/nebula -config /tmp/r.yml"

# 4. Publish harness (trên máy dev) rồi scp vào VM:  dotnet publish -c Release -r linux-x64 -o publish
#    (harness/ csproj ref Nebula + Crypto; xem harness/Program.cs)
./harness . 127.0.0.1:4242
#    → "SUCCESS: real nebula accepted our Noise IX handshake and we completed it."

# 5. Kiểm log nebula:  docker logs nebula-responder | grep -i handshake
# 6. Dọn:  docker rm -f nebula-responder
```

## Ghi chú
- `responder.yml`: `tun.disabled: true` ⇒ nebula KHÔNG cần root/CAP_NET_ADMIN, vẫn listen UDP 4242 + handshake.
- 2 host static biết IP nhau (hoặc responder là lighthouse) **handshake trực tiếp**, KHÔNG cần lighthouse discovery
  cho lab 2-node (nebula chấp nhận handshake từ mọi cert ký bởi CA tin cậy).
- Cert/key/binary **KHÔNG commit** (xem `.gitignore`) — chỉ commit config + script + harness source.
