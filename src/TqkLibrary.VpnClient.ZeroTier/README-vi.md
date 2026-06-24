# TqkLibrary.VpnClient.ZeroTier

Thư viện **protocol ZeroTier V1 (x25519)** thuần .NET — hiện thực hai tầng giao thức ZeroTier ở mức codec:
**VL1** (transport: định danh **C25519**, dẫn xuất **địa chỉ 40-bit memory-hard**, gói UDP mã hóa+xác thực
**Salsa20/12 + Poly1305**, verb **HELLO**) và **VL2** (virtual L2: **network-id 64-bit**, frame Ethernet trên verb
**FRAME**). Đây là project protocol-level cho driver **V.7.3** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.3).
Driver runtime (UDP transport, root/planet discovery, join network controller, `IEthernetChannel` ghép L2 fabric,
supervisor F.6, `UseZeroTier`) là phase (b) — **chưa làm**.

> **Trạng thái:** **phase (a) protocol XONG OFFLINE** (2026-06-24) — 29 test offline xanh, build xanh ns2.0 + net8.
> **INTEROP UNVERIFIED — live STAGED** (VM lab down trong phiên): primitive **Salsa20 đã KAT ECRYPT chuẩn**
> (high-confidence), nhưng phần ráp xung quanh **chưa đối chiếu ZeroTier thật**: (a) address derivation chưa KAT vs
> `zerotier-idtool`; (b) VL1/VL2 wire chưa đối chiếu `zerotier-one`. Khi VM lên sẽ validate (xem cuối). **Tái dùng**
> [`Salsa20`](../TqkLibrary.VpnClient.Crypto/Salsa20.cs#L24) + [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15)
> + BouncyCastle `Poly1305` + `SHA512` BCL — **không** viết lại crypto.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Nebula](../TqkLibrary.VpnClient.Nebula)/[Tinc](../TqkLibrary.VpnClient.Tinc)): các khối
giao thức + codec thuần, **không** I/O socket. VL1 packet codec là **seal/open đối xứng** (driver bơm datagram
vào/ra). Khác Nebula/WireGuard (Noise + AEAD trên `IPacketChannel` L3): ZeroTier là **overlay L2** — VL1 chở khung
Ethernet (VL2 FRAME) để driver ghép vào [Ethernet fabric](../TqkLibrary.VpnClient.Ethernet) (`IEthernetChannel`).
Cipher gói = **Salsa20/12 + Poly1305 phi-AEAD-chuẩn** (poly key = keystream block 0, tag 8B truncated trên ciphertext)
— KHÔNG phải ChaCha20-Poly1305 RFC 8439.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`Salsa20`](../TqkLibrary.VpnClient.Crypto/Salsa20.cs#L24) (VL1 /12 + identity hash /20), [`Curve25519DhGroup`](../TqkLibrary.VpnClient.Crypto/Noise/Curve25519DhGroup.cs#L15) (VL1 key agreement), BouncyCastle `Poly1305` (MAC gói), `SHA512` BCL (identity hash + KDF) |
| Được dùng bởi | `Drivers.ZeroTier` (V.7.3 phase b — chưa làm) | driver sẽ lắp UDP transport + root discovery + network-join quanh các codec này, ghép L2 fabric |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.ZeroTier/
├─ Identity/
│  ├─ ZeroTierIdentityCodec.cs        parse/encode identity (idtool-string "addr:0:pub[:priv]" + binary)
│  ├─ ZeroTierAddressDerivation.cs    memory-hard hash (SHA-512 + Salsa20/20 buffer 2MB) → address + hashcash digest[0]<17
│  └─ Models/
│     ├─ ZeroTierAddress.cs           địa chỉ node 40-bit (read/write/parse, reserved-rules: !=0, MSB!=0xff)
│     └─ ZeroTierIdentity.cs          pubkey 64B = Curve25519(32) ‖ Ed25519(32); privkey 64B tương ứng
├─ Vl1/
│  ├─ Vl1PacketCodec.cs               seal/open gói VL1 (Salsa20/12 + Poly1305, poly key = keystream block0, tag 8B)
│  ├─ Vl1KeyDerivation.cs             shared key = SHA-512(X25519(myPriv, peerPub)); 32B đầu = Salsa20 key
│  ├─ HelloMessageCodec.cs            codec body verb HELLO (version + timestamp + identity nhúng)
│  ├─ Enums/
│  │  ├─ Vl1CipherSuite.cs            low 3 bit byte18: Poly1305None=0 / Salsa2012Poly1305=1 / None=2
│  │  └─ Vl1Verb.cs                   low 5 bit verb byte: NOP/HELLO/ERROR/OK/WHOIS/FRAME/EXT_FRAME/MULTICAST_FRAME…
│  └─ Models/
│     ├─ Vl1Header.cs                 header 27B clear + verb byte (packetId/dest/src/cipher/MAC offsets)
│     └─ HelloMessage.cs              POCO HELLO (protocol/version/timestamp/identity)
└─ Vl2/
   ├─ Vl2FrameCodec.cs               codec body FRAME (networkId‖flags‖etherType‖frame) + DeriveMac per-network
   └─ Models/
      ├─ NetworkId.cs                network-id 64-bit (controller-address 40-bit ‖ index 24-bit)
      └─ Vl2Frame.cs                 POCO khung VL2 (network/etherType/frameData + src/dst node address)
```

## Bảng type chính

| Type | Vai trò |
|------|---------|
| [`ZeroTierAddress`](Identity/Models/ZeroTierAddress.cs#L14) | địa chỉ node 40-bit — read/write 5B BE, parse 10-hex, `IsValid` (reserved-rules) |
| [`ZeroTierIdentity`](Identity/Models/ZeroTierIdentity.cs#L12) | identity = address + pubkey 64B (Curve25519‖Ed25519) + privkey tùy chọn |
| [`ZeroTierIdentityCodec`](Identity/ZeroTierIdentityCodec.cs#L20) | codec idtool-string + binary (round-trip public/private) |
| [`ZeroTierAddressDerivation`](Identity/ZeroTierAddressDerivation.cs#L30) | memory-hard hash → digest 64B + address; hashcash `digest[0]<17` |
| [`Vl1Header`](Vl1/Models/Vl1Header.cs#L20) | header VL1: packetId/dest/src 40-bit/cipher byte/MAC 8B/verb byte |
| [`Vl1PacketCodec`](Vl1/Vl1PacketCodec.cs#L31) | seal/open Salsa20/12 + Poly1305 (tamper/MAC reject) |
| [`Vl1KeyDerivation`](Vl1/Vl1KeyDerivation.cs#L16) | C25519 agreement → SHA-512 shared key (đối xứng 2 đầu) |
| [`HelloMessageCodec`](Vl1/HelloMessageCodec.cs#L13) | codec body HELLO |
| [`NetworkId`](Vl2/Models/NetworkId.cs#L10) | network-id 64-bit + controller-address split |
| [`Vl2FrameCodec`](Vl2/Vl2FrameCodec.cs#L17) | codec FRAME body + `DeriveMac` per-network |

## Bảng chuẩn / behavior ZeroTier (clean-room — đọc spec/prose, KHÔNG copy BSL source)

| Hạng mục | Giá trị (ZeroTier V1, x25519) |
|----------|-------------------------------|
| Identity pubkey | 64B = Curve25519(32, ECDH) ‖ Ed25519(32, sign); type byte `0x00` |
| Address | 40-bit (5B) = `digest[59..64]` của memory-hard hash; reserved: `!=0`, MSB `!=0xff` |
| Memory-hard hash | `digest = SHA-512(pubkey)`; Salsa20/**20** key=`digest[32..64]` iv=`digest[0..8]`; genmem **2MB**; fill 31250 vòng; shuffle 125000 vòng (idx1=`n1%8`, idx2=`n2%250000`, swap 8B digest↔genmem); re-encrypt digest; hashcash `digest[0] < 17` |
| VL1 header (27B clear + verb) | `[0..8)` packetId/IV ‖ `[8..13)` dest 40-bit ‖ `[13..18)` src 40-bit ‖ `[18]` flags(5)+cipher(3) ‖ `[19..27)` MAC 8B ‖ `[27]` verb byte (flags 3 + verb 5) |
| VL1 cipher | Salsa20/**12**, nonce = packetId 8B; poly key = keystream block 0 (32B); payload mã hóa bằng keystream tiếp; Poly1305 trên ciphertext, tag truncate 8B |
| VL1 key | per-node = `SHA-512(X25519(myCurve25519Priv, peerCurve25519Pub))`; 32B đầu = Salsa20 key |
| VL1 verb | NOP=0, **HELLO=1**, ERROR=2, OK=3, WHOIS=4, RENDEZVOUS=5, FRAME=6, EXT_FRAME=7, MULTICAST_FRAME=0x0E |
| HELLO body | `protocolVer(1) ‖ major(1) ‖ minor(1) ‖ revision(2 BE) ‖ timestamp(8 BE) ‖ identity(addr5‖type1‖pub64)` — Poly1305None (chưa có session key) |
| VL2 network-id | 64-bit = controller-address(40-bit) ‖ index(24-bit); in 16-hex |
| VL2 FRAME body | `networkId(8) ‖ flags(1) ‖ etherType(2 BE) ‖ frameData`; src/dst node address từ VL1 header |
| VL2 MAC | 48-bit: low 40-bit = node address; top octet seed từ network-id, unicast (I/G=0) + locally-administered (U/L=1) |

## Luồng seal/open VL1 (Salsa20/12 + Poly1305)

1. **Seal** [`Vl1PacketCodec.Seal`](Vl1/Vl1PacketCodec.cs#L40): ghi header clear (cipher = `Salsa2012Poly1305`) →
   Salsa20/12 init (key, nonce=packetId) → keystream block 0 = poly key (32B) → mã hóa `verb‖payload` bằng keystream
   tiếp → Poly1305(ciphertext) truncate 8B vào MAC `[19..27)`.
2. **Open** [`Vl1PacketCodec.Open`](Vl1/Vl1PacketCodec.cs#L81): đọc header clear → cùng key-stream → tính lại MAC
   trên ciphertext, so khớp (fixed-time) **trước** khi giải mã → giải mã `verb‖payload`.

## Trạng thái & ghi chú

- **Phase (a) protocol**: XONG OFFLINE. 29 test (address read/write/validity, identity string+binary round-trip,
  address derivation self-consistency + structure, **VL1 self-pair seal/open + tamper/MAC/wrong-key reject**, KDF
  symmetric, HELLO/VL2 round-trip, DeriveMac). **Self-pair bắt 1 off-by-one** packet-len (verb byte bị đếm 2 lần)
  trước commit.
- **INTEROP UNVERIFIED — live STAGED** (VM lab down): Salsa20 nền đã KAT ECRYPT chuẩn, nhưng (a) **address derivation**
  thứ tự genmem fill/shuffle + split key/iv suy từ prose, **chưa KAT vs `zerotier-idtool`** (không có sample identity
  offline); (b) **VL1 packet** offset/key-stream-split/MAC-truncation **chưa đối chiếu `zerotier-one` thật**; (c) **VL2**
  `DeriveMac` seed first-octet là clean-room. **Bài học V.1–V.6**: bug interop self-pair offline KHÔNG bắt. Khi VM lên:
  KAT address bằng identity `zerotier-idtool` thật + đối chiếu VL1 HELLO với `zerotier-one`; lab `lab/zerotier/`
  (Dockerfile zerotier-one + idtool) chưa dựng.
- **Phase (b) driver runtime**: chưa làm — UDP transport + root/planet discovery (tĩnh-trước) + join network controller
  → `IEthernetChannel` ghép [Ethernet fabric](../TqkLibrary.VpnClient.Ethernet) + supervisor F.6 + `UseZeroTier` + demo
  scheme.
- **Cert/identity P384 (ZeroTier 2.x)** KHÔNG hiện thực — mới làm V1 x25519 (Curve25519/Ed25519/Salsa20) như roadmap.
