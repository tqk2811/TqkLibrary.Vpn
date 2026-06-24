# TqkLibrary.VpnClient.Tinc

Thư viện **protocol tinc 1.1** thuần .NET — hiện thực **SPTPS** (Simple Peer-to-Peer Security): handshake
**KEX → SIG** (Curve25519 ECDH ephemeral + chữ ký Ed25519 + key expansion **HMAC-SHA-512 TLS-PRF**), **record cipher
ChaCha-Poly1305 biến thể tinc** (KHÔNG phải RFC 8439), codec **meta-connection** (request line TCP) và parser
**host-config / khóa Ed25519**. Đây là project protocol-level cho driver **V.7.2** (xem
[`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.2). Driver runtime (TCP meta auto-mesh, UDP data, bảng route,
`IPacketChannel`/`IEthernetChannel`, supervisor F.6) là phase (b) — **chưa làm**.

> **Trạng thái:** **phase (a) protocol XONG** (2026-06-24) — 28 test offline xanh, build xanh ns2.0 + net8.
> **Validate live SPTPS handshake với tincd 1.1 thật: CHƯA chạy** (VM lab không truy cập được trong phiên; lab +
> harness đã chuẩn bị sẵn ở [`lab/tinc`](../../lab/tinc)). **Tái dùng nguyên**
> [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (X25519 DH) +
> [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) (KEX SIG) +
> [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8) (data plane). Cipher ChaCha-Poly1305
> biến thể tinc tự viết trên BouncyCastle `ChaChaEngine` + `Poly1305` (nền cipher đã KAT chuẩn djb/RFC 8439).

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [WireGuard](../TqkLibrary.VpnClient.WireGuard)/[Nebula](../TqkLibrary.VpnClient.Nebula)):
các khối giao thức thuần, **không** I/O socket. Handshake SPTPS là **state machine đối xứng thuần** (driver bơm
record vào/ra; test + harness chạy initiator↔responder/tincd). Khác Nebula: KHÔNG dùng Noise — SPTPS là sơ đồ riêng
kiểu TLS-1.2 rút gọn (KEX/SIG/ACK record, TLS-PRF HMAC-SHA-512), cipher **ChaCha-Poly1305 phi chuẩn** (nonce =
seqno 8-byte BE kiểu djb, tag chỉ trên ciphertext — không AAD/độn-độ-dài như RFC 8439).

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (X25519 ECDH ephemeral), [`Ed25519Signer`](../TqkLibrary.VpnClient.Crypto/Noise/Ed25519Signer.cs#L15) (ký/verify SIG), [`AntiReplayWindow`](../TqkLibrary.VpnClient.Crypto/AntiReplayWindow.cs#L8) (replay UDP data), `BouncyCastle` `ChaChaEngine`/`Poly1305` (record cipher), `HMACSHA512` BCL (PRF) |
| Được dùng bởi | `Drivers.Tinc` (V.7.2 phase b — chưa làm) | driver sẽ lắp ráp TCP meta + UDP data + route table quanh các codec/handshake này |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.Tinc/
├─ Sptps/
│  ├─ SptpsConstants.cs            hằng wire (version/ECDH/sig size/cipher key/"key expansion")
│  ├─ SptpsHandshake.cs            state machine SPTPS 1 phía (CreateKex/ConsumeKex/CreateSig/ConsumeSig + keys)
│  ├─ SptpsPrf.cs                  TLS-PRF HMAC-SHA-512 key expansion (hmac[0]=HMAC(zeros64‖seed), out=hmac[1‖2‖…])
│  ├─ TincChaChaPoly1305.cs        record cipher biến thể tinc (nonce seqno 8B BE djb, poly key block0, tag-on-ciphertext)
│  ├─ SptpsRecordLayer.cs          framing TCP stream (len(2)‖type‖data; mã hóa sau handshake; seqno in/out riêng)
│  ├─ SptpsDatagramRecordLayer.cs  framing UDP data (seqno(4 BE)‖encrypt(type‖data)‖tag(16); anti-replay)
│  ├─ Enums/
│  │  ├─ SptpsRecordType.cs        Handshake=128/Alert=129/Close=130
│  │  └─ SptpsDecodeResult.cs      Ok/NeedMore/AuthFailed
│  └─ Models/SptpsKex.cs           KEX 65B = version(1)‖nonce(32)‖pubkey(32)
├─ Meta/
│  ├─ TincMetaRequest.cs           codec request line ("0 name 17.7\n", ADD_EDGE/ADD_SUBNET/ACK…)
│  └─ Enums/TincRequestType.cs     request_t (ID=0…MTU_INFO=23, protocol.h)
└─ Hosts/
   └─ TincHostConfig.cs            parse hosts/<name>: Ed25519PublicKey (base64 32B)/Address/Port/Subnet, skip RSA PEM
```

## Bảng type chính

| Type | Vai trò |
|------|---------|
| [`SptpsHandshake`](Sptps/SptpsHandshake.cs#L21) | KEX→SIG→derive: tạo/đọc KEX, ký/verify SIG (transcript `fill_msg`), seed KDF, tách khóa hướng |
| [`SptpsPrf`](Sptps/SptpsPrf.cs#L17) | TLS-P_hash HMAC-SHA-512 — expand shared secret + seed → 128B key material |
| [`TincChaChaPoly1305`](Sptps/TincChaChaPoly1305.cs#L18) | cipher record (Encrypt/Decrypt theo seqno; biến thể tinc, không RFC 8439) |
| [`SptpsRecordLayer`](Sptps/SptpsRecordLayer.cs#L16) | record TCP stream (handshake plaintext + app encrypted, seqno) |
| [`SptpsDatagramRecordLayer`](Sptps/SptpsDatagramRecordLayer.cs#L16) | record UDP data plane (seqno prefix + replay window) |
| [`SptpsKex`](Sptps/Models/SptpsKex.cs#L9) | codec KEX 65B |
| [`TincMetaRequest`](Meta/TincMetaRequest.cs#L13) | codec request line meta (ID/ADD_EDGE/…) |
| [`TincHostConfig`](Hosts/TincHostConfig.cs#L11) | parse host file (Ed25519PublicKey/Address/Subnet) |

## Bảng chuẩn / behavior tinc (clean-room — đọc spec + behavior, KHÔNG copy GPL)

| Hạng mục | Giá trị (tinc 1.1, suite Ed25519/Curve25519) |
|----------|----------------------------------------------|
| ECDH | Curve25519 (X25519), `ECDH_SIZE`=32 |
| Chữ ký | Ed25519, `ECDSA_SIZE`=64 |
| Cipher | ChaCha-Poly1305 biến thể tinc, key 64B (`CHACHA_POLY1305_KEYLEN`) |
| PRF | TLS-1.2 P_hash trên HMAC-SHA-512 |
| KEX (65B) | `version(0) ‖ nonce(32) ‖ pubkey(32)` |
| SIG transcript | `fill_msg`: `initiator_flag(1) ‖ kex0(65) ‖ kex1(65) ‖ label`; ký dùng `my_kex` trước, verify peer dùng `his_kex` trước + cờ đảo |
| KDF seed | `"key expansion"(13, không NUL) ‖ initiator_nonce(32) ‖ responder_nonce(32) ‖ label` |
| PRF expand | `hmac[0]=HMAC(secret, zeros(64)‖seed)`, `hmac[n]=HMAC(secret, hmac[n-1]‖seed)`, out=`hmac[1]‖hmac[2]…` |
| Key split | initiator out=key1/in=key0; responder out=key0/in=key1 |
| Cipher nonce | seqno (uint64) big-endian vào IV 8-byte djb; poly key = keystream block 0; message từ counter 1; tag = Poly1305(ciphertext) |
| Record TCP | `len(2 BE) ‖ type(1)` (handshake plaintext) / `len(2 BE) ‖ encrypt(type‖data) ‖ tag(16)` (sau handshake) |
| Record UDP | `seqno(4 BE) ‖ encrypt(seqno, type‖data) ‖ tag(16)`, overhead 21 |
| Meta flow | TCP → ID cleartext `"0 <name> 17.7\n"` → đọc peer ID → SPTPS (outgoing = initiator); label `"tinc TCP key expansion <init> <resp>"` + NUL |
| Request codes | ID=0, METAKEY=1, …, ADD_SUBNET=10, ADD_EDGE=12, KEY_CHANGED=14, …, MTU_INFO=23 (protocol.h) |
| Host file | `Ed25519PublicKey` = base64 không padding (43 ký tự = 32B); `Address`/`Port`/`Subnet`; bỏ qua RSA PEM legacy |

## Luồng SPTPS handshake (initiator = client của ta)

1. [`CreateKex`](Sptps/SptpsHandshake.cs#L97) → ephemeral X25519 + nonce → gửi KEX (record handshake plaintext).
2. Nhận KEX server → [`ConsumeKex`](Sptps/SptpsHandshake.cs#L112): ECDH shared secret + [`SptpsPrf.Expand`](Sptps/SptpsPrf.cs#L17) → 128B key material.
3. [`CreateSig`](Sptps/SptpsHandshake.cs#L125) → Ed25519 ký transcript `[1‖my_kex‖his_kex‖label]` → gửi SIG.
4. Nhận SIG server → [`ConsumeSig`](Sptps/SptpsHandshake.cs#L138): verify `[0‖server_kex‖client_kex‖label]` bằng pubkey server.
5. [`EnableEncryption`](Sptps/SptpsRecordLayer.cs#L33) với [`OutCipherKey`](Sptps/SptpsHandshake.cs#L150)/[`InCipherKey`](Sptps/SptpsHandshake.cs#L153) → record app mã hóa 2 chiều.

## Trạng thái & ghi chú

- **Phase (a) protocol**: XONG. 28 test offline (handshake self-interop + crossed keys, cipher round-trip/tamper/seqno,
  record TCP/UDP framing + replay, KEX codec, PRF, meta/host codec, **KAT ChaCha20 djb + Poly1305 chuẩn**).
- **Live**: chưa validate (VM lab down trong phiên). Lab [`lab/tinc`](../../lab/tinc) (Dockerfile build tinc 1.1pre18 từ
  source vì apt chỉ có 1.0.36 không SPTPS) + harness publish linux-x64 đã sẵn sàng.
- **Phase (b) driver runtime**: chưa làm — TCP meta auto-mesh (ADD_EDGE/ADD_SUBNET), UDP data + fallback TCP, bảng
  route/subnet → `IPacketChannel` (router) / `IEthernetChannel` (switch — tái dùng [Ethernet fabric](../TqkLibrary.VpnClient.Ethernet)),
  supervisor F.6, `UseTinc`, demo scheme.
- **tinc 1.0 legacy** (RSA + sơ đồ cũ) KHÔNG hiện thực — ưu tiên 1.1 SPTPS như roadmap.
