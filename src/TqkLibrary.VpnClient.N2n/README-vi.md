# TqkLibrary.VpnClient.N2n

Thư viện **protocol n2n v3 (ntop)** thuần .NET — hiện thực **codec wire** cho các thông điệp control/data của mạng mesh
L2 n2n: **supernode** + **edge**. Mỗi gói = **common header 24B** (`version=3 ‖ ttl ‖ flags(2B BE) ‖ community(20B
null-pad)`, packet-type nằm ở 5 bit thấp của `flags`) nối với body theo từng loại:
**REGISTER_SUPER / REGISTER_SUPER_ACK / PEER_INFO / REGISTER / REGISTER_ACK / PACKET** — tất cả **big-endian**. Đây là
project protocol-level cho driver **V.7.4** (xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.7.4).
Driver runtime (UDP transport, REGISTER_SUPER lifecycle, `IEthernetChannel` ghép L2 fabric, supervisor F.6, `UseN2n`) là
phase (b) — **XONG**, VALIDATE LIVE L2 full-tunnel ICMP 2 chiều ([`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n)).
P2P UDP hole-punching + header encryption (`-H`) còn lại (future).

> **Trạng thái:** **phase (a) protocol XONG — REGISTER_SUPER VALIDATE LIVE** (2026-06-24) — 21 test offline xanh,
> build xanh ns2.0 + net8. **Đối chiếu với `n2n` v3.1.1 thật** (lab [`lab/n2n`](../../lab/n2n)): supernode thật **CHẤP
> NHẬN REGISTER_SUPER** của client .NET (community `labnet`, transform NULL, header-enc OFF) — supernode log
> `Rx REGISTER_SUPER` + `created edge` + `Tx REGISTER_SUPER_ACK`; client **decode REGISTER_SUPER_ACK** thật: cookie
> echoed đúng, supernode gán `dev_addr` 10.209.172.184/24, lifetime, supernode MAC, public socket của edge. **3 KAT
> golden byte-exact** (REGISTER_SUPER edge thật 79B + REGISTER_SUPER_ACK supernode thật 58B). **Tái dùng**
> [`AesCbcCipher`](../TqkLibrary.VpnClient.Crypto/AesCbcCipher.cs#L10) cho transform AES — **không** viết lại AES.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Nebula](../TqkLibrary.VpnClient.Nebula)/[Tinc](../TqkLibrary.VpnClient.Tinc)/[ZeroTier](../TqkLibrary.VpnClient.ZeroTier)):
khối codec thuần, **không** I/O socket. Codec là **encode/decode đối xứng** cho từng message type (driver bơm datagram
vào/ra UDP). Giống ZeroTier, n2n là **overlay L2** — PACKET chở khung Ethernet để driver ghép vào
[Ethernet fabric](../TqkLibrary.VpnClient.Ethernet) (`IEthernetChannel`). Khác ZeroTier (Salsa20/Poly1305 trên từng
gói): n2n tách rời — **control message không mã hóa** (registration/ACK là cleartext khi `-H` off), chỉ **payload
PACKET** được transform (NULL/AES-CBC/ChaCha20/Speck) bảo vệ. Bản này hiện thực **header-encryption OFF** + transform
**NULL** và **AES-CBC**.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Crypto](../TqkLibrary.VpnClient.Crypto) | [`AesCbcCipher`](../TqkLibrary.VpnClient.Crypto/AesCbcCipher.cs#L10) cho transform AES (`N2nAesTransform`) |
| Được dùng bởi | [`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n) (V.7.4 phase b — XONG, VALIDATE LIVE L2 full-tunnel) | driver lắp UDP transport + REGISTER_SUPER lifecycle + keepalive quanh codec này, ghép L2 fabric (ARP + VirtualHost) → facade L3 |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.N2n/
├─ N2nPacketCodec.cs                   encode/decode mọi message type (common header 24B + body, big-endian)
├─ Wire/
│  ├─ N2nConstants.cs                  hằng số (version 3, ttl, community 20B, mac 6B, desc 16B, cookie 4B, header 24B)
│  ├─ Enums/
│  │  ├─ N2nPacketType.cs              packet-type (low 5 bit flags): RegisterSuper=5/ACK=7/PeerInfo=10/Register=1/PACKET=3…
│  │  ├─ N2nFlags.cs                   bit cao flags: TypeMask 0x1f / FromSupernode 0x20 / Socket 0x40 / Options 0x80
│  │  └─ N2nTransformId.cs             transform id PACKET body: Null=1 / Aes=3 / ChaCha20=4 / Speck=5 (chỉ Null/Aes hiện thực)
│  └─ Models/
│     ├─ N2nCommonHeader.cs            header 24B clear (version/ttl/flags BE/community null-pad)
│     ├─ N2nSock.cs                    n2n_sock_t (family marker v4/v6 + port BE + addr 4/16B)
│     ├─ N2nAuth.cs                    n2n_auth_t (scheme 2B + token_size 2B + token); simple-id challenge 16B mặc định
│     ├─ N2nIpSubnet.cs                n2n_ip_subnet_t (net_addr 4B BE + bitlen 1B)
│     ├─ N2nRegisterSuper.cs           body REGISTER_SUPER (cookie/edgeMac/sock?/devAddr/devDesc/auth/keyTime)
│     ├─ N2nRegisterSuperAck.cs        body REGISTER_SUPER_ACK (cookie/srcMac/devAddr/lifetime/sock/auth/numSn/keyTime)
│     ├─ N2nRegister.cs                body REGISTER edge↔edge (cookie/src/dstMac/sock?/devAddr/devDesc)
│     ├─ N2nRegisterAck.cs             body REGISTER_ACK edge↔edge (cookie/src/dstMac/sock?)
│     ├─ N2nPeerInfo.cs                body PEER_INFO (aflags/mac/sock/preferredSock/load/uptime)
│     └─ N2nPacket.cs                  body PACKET (src/dstMac/sock?/compression/transform + payload Ethernet frame)
└─ Transform/
   ├─ Interfaces/IN2nTransform.cs      Encode/Decode payload PACKET + Id
   ├─ N2nNullTransform.cs              transform NULL (identity, frame clear)
   └─ N2nAesTransform.cs               transform AES-CBC null-IV + 16B random preamble (tái dùng AesCbcCipher)
```

## Bảng type

| Type | Kind | Vai trò |
|------|------|---------|
| [`N2nPacketCodec`](N2nPacketCodec.cs#L19) | class | Encode/Decode tất cả message type; stateless, dùng lại |
| [`N2nCommonHeader`](Wire/Models/N2nCommonHeader.cs#L16) | class | Header 24B clear (cleartext-header form, `-H` off) |
| [`N2nSock`](Wire/Models/N2nSock.cs#L13) | class | sock v4/v6, `FromEndPoint`/`ToEndPoint` |
| [`N2nAuth`](Wire/Models/N2nAuth.cs#L14) | class | auth block; `SimpleIdRandom()` token 16B |
| [`N2nIpSubnet`](Wire/Models/N2nIpSubnet.cs#L13) | struct | subnet (addr 4B + bitlen 1B), `Unset` |
| [`N2nRegisterSuper`](Wire/Models/N2nRegisterSuper.cs#L11) | class | body edge→supernode |
| [`N2nRegisterSuperAck`](Wire/Models/N2nRegisterSuperAck.cs#L13) | class | body supernode→edge |
| [`N2nPeerInfo`](Wire/Models/N2nPeerInfo.cs#L12) | class | body PEER_INFO (P2P setup) |
| [`N2nPacket`](Wire/Models/N2nPacket.cs#L11) | class | body PACKET (khung Ethernet) |
| [`IN2nTransform`](Transform/Interfaces/IN2nTransform.cs#L9) | interface | transform payload PACKET |
| [`N2nNullTransform`](Transform/N2nNullTransform.cs#L11) | class | transform NULL (clear) |
| [`N2nAesTransform`](Transform/N2nAesTransform.cs#L18) | class | transform AES-CBC (null-IV + preamble) |
| [`N2nPacketType`](Wire/Enums/N2nPacketType.cs#L9) / [`N2nFlags`](Wire/Enums/N2nFlags.cs#L9) / [`N2nTransformId`](Wire/Enums/N2nTransformId.cs#L7) | enum | type / flag bits / transform id |

## Bảng chuẩn / wire format (n2n v3, đối chiếu source `n2n_typedefs.h` + `wire.c` — đọc spec, KHÔNG copy GPL)

| Thành phần | Layout on-wire |
|-----------|----------------|
| Common header (24B) | `version(1)=3 ‖ ttl(1) ‖ flags(2 BE) ‖ community(20 null-pad)`; `flags = (pkt-type & 0x1f) \| flag-bits` |
| REGISTER_SUPER | `…header ‖ cookie(4) ‖ edgeMac(6) ‖ [sock — nếu SOCKET flag] ‖ devAddr(5) ‖ devDesc(16) ‖ auth ‖ keyTime(4)` |
| REGISTER_SUPER_ACK | `…header ‖ cookie(4) ‖ srcMac(6) ‖ devAddr(5) ‖ lifetime(2) ‖ sock ‖ auth ‖ numSn(1) ‖ sock×numSn ‖ keyTime(4)` |
| REGISTER / _ACK | `…header ‖ cookie(4) ‖ srcMac(6) ‖ dstMac(6) ‖ [sock] ‖ (REGISTER: devAddr(5) ‖ devDesc(16))` |
| PEER_INFO | `…header ‖ aflags(2) ‖ mac(6) ‖ sock ‖ preferredSock ‖ load(4) ‖ uptime(4)` |
| PACKET | `…header ‖ srcMac(6) ‖ dstMac(6) ‖ [sock] ‖ compression(1) ‖ transform(1) ‖ payload(transform-encoded)` |
| sock | `family(2 BE: 0=v4, 0x8000=v6) ‖ port(2 BE) ‖ addr(4 v4 / 16 v6)` |
| auth | `scheme(2 BE) ‖ token_size(2 BE) ‖ token(token_size)`; simple-id (1) + 16B token |
| Transform AES (id 3) | `AES-CBC(null IV)` của `random preamble(16) ‖ frame ‖ zero-pad→block`; output = ciphertext (preamble = IV ngầm) |

## Luồng nội bộ (REGISTER_SUPER → ACK)

1. [`EncodeRegisterSuper`](N2nPacketCodec.cs#L33) ghi common header (type 5, no Socket flag nếu sock null) + cookie +
   edgeMac + devAddr `Unset` + devDesc + auth `SimpleIdRandom` + keyTime 0 → 79B.
2. Driver/harness gửi UDP tới supernode `:7654`.
3. Supernode đáp REGISTER_SUPER_ACK (58B, flags = FromSupernode|Socket).
4. [`TryDecodeRegisterSuperAck`](N2nPacketCodec.cs#L88) đọc cookie (đối chiếu cái đã gửi), srcMac (supernode MAC),
   devAddr (IP gán), lifetime, sock (public socket của edge), auth, numSn + extra supernodes, keyTime.

## Trạng thái & ghi chú

- **Phase (a) protocol XONG + REGISTER_SUPER validate live** (2026-06-24). Build xanh **ns2.0 + net8**; 21 test offline
  (round-trip mọi pkt-type + wire-layout invariants + AES self-pair 2 chiều + 3 KAT golden live).
- **Header encryption (`-H`) KHÔNG hiện thực**: n2n v3 dùng **Speck** + **Pearson-256 hash** key-derivation cho header
  encryption — cả hai chưa có trong Crypto, và byte-exact rủi ro cao. Validate live chạy với header-enc OFF (supernode/
  edge không truyền `-H`). Nếu sau cần header-enc: thêm Speck + Pearson-256 vào Crypto, hiện thực framing
  `header_encryption.c` (magic `n2__` + checksum Pearson-64 + SPECK-CTR từ offset 16).
- **Transform key-derivation KHÔNG hiện thực**: `N2nAesTransform` nhận AES key sẵn (16/24/32B); n2n derive key bằng
  Pearson-256 của password (out of scope đợt này). Validate live dùng transform NULL.
- **Driver runtime (phase b) XONG** ([`Drivers.N2n`](../TqkLibrary.VpnClient.Drivers.N2n)): UDP transport + REGISTER_SUPER
  lifecycle + keepalive + ghép `IEthernetChannel` vào L2 fabric (ARP + VirtualHost static-IP) + supervisor F.6 + `UseN2n`
  + demo scheme `.n2n` — **VALIDATE LIVE L2 full-tunnel ICMP 2 chiều** vs n2n v3.1.1 (2 bug interop keepalive-auth +
  dev_addr-static sửa qua live). **Còn lại (future)**: P2P UDP hole-punching (QUERY_PEER/PEER_INFO) + header encryption (`-H`).
- Mỗi type 1 file; instance method (codec/transform) sau interface (`IN2nTransform`). Codec stateless.
