# TqkLibrary.VpnClient.OpenVpn

Thư viện **protocol OpenVPN** thuần .NET (tương thích OpenVPN community server) — **không dùng PPP**. Control channel (TLS) + data channel ghép trên một socket UDP/TCP, demux theo byte opcode đầu. Đây là project protocol-level cho driver **V.2** (đang xây theo phase, xem [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2).

> **Trạng thái:** đang ở **V2.a — control-channel reliability layer**. Hiện đã có: codec gói control (opcode/key-id + session-id + ACK array + packet-id + payload). Reliability state machine (retransmit + in-order delivery + ACK) là phần kế tiếp của V2.a; TLS-in-control (V2.b), tls-auth/tls-crypt (V2.c), data channel AEAD (V2.d)… chưa làm.

## Vị trí kiến trúc

`PROTOCOL`-layer (ngang hàng [Ipsec](../TqkLibrary.VpnClient.Ipsec)/[L2tp](../TqkLibrary.VpnClient.L2tp)/[Ppp](../TqkLibrary.VpnClient.Ppp)): các khối giao thức thuần, **không** I/O socket — driver `Drivers.OpenVpn` (V.2, chưa có) sẽ lắp ráp thành tunnel sống. Reliability layer của OpenVPN tương tự vai trò control-channel của [L2tp](../TqkLibrary.VpnClient.L2tp) (Ns/Nr + retransmit) nhưng dùng **packet-id 32-bit + ACK array** thay cho sequence 16-bit.

## Phụ thuộc

| Hướng | Project | Lý do |
|-------|---------|-------|
| Dùng | [Abstractions](../TqkLibrary.VpnClient.Abstractions) | (cho các phase sau: `IPacketChannel`, exceptions, `IHostResolver`) |
| Được dùng bởi | `Drivers.OpenVpn` (V.2, **chưa có**) | driver lắp ráp control/data plane |

## Cấu trúc thư mục

```
TqkLibrary.VpnClient.OpenVpn/
├─ OpenVpnPacketCodec.cs        Codec gói control: opcode/key-id, session-id, ACK array, packet-id, payload
├─ Enums/
│  └─ OpenVpnOpcode.cs          5-bit opcode (P_CONTROL/P_ACK/HARD_RESET/SOFT_RESET/P_DATA…)
└─ Models/
   └─ OpenVpnControlPacket.cs   Gói control đã decode (session-id, acks, remote-session-id, packet-id, payload)
```

## Bảng type

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `OpenVpnOpcode` | enum 5-bit opcode (giá trị 1–11 theo wire protocol) | [Enums/OpenVpnOpcode.cs:8](Enums/OpenVpnOpcode.cs#L8) |
| `OpenVpnControlPacket` | model gói control đã decode; `IsAckOnly` cho P_ACK_V1 | [Models/OpenVpnControlPacket.cs:10](Models/OpenVpnControlPacket.cs#L10) |
| `OpenVpnPacketCodec` | static codec: `Header`/`ReadOpcode`/`ReadKeyId` pack byte đầu; `IsControlOpcode`; `EncodeControl`/`TryDecodeControl` | [OpenVpnPacketCodec.cs:17](OpenVpnPacketCodec.cs#L17) |

## Wire format (control packet)

```
opcode|key_id (1) | session_id (8) | ack_len (1) | acked_ids (4·M) | [remote_session_id (8) nếu M>0]
                  | [packet_id (4) | payload (…)]   ← chỉ P_CONTROL/reset; P_ACK_V1 bỏ 2 trường cuối
```

- **Byte đầu**: 5-bit opcode (cao) + 3-bit key_id (thấp, tới 8 phiên key chồng cho rekey).
- **session_id**: 64-bit của bên gửi. `remote_session_id` (của peer) chỉ xuất hiện khi có ≥1 ACK.
- **P_ACK_V1**: chỉ mang acks (không packet-id, không payload).
- **TCP** (phase sau): mỗi gói prefix 16-bit length; **UDP**: 1 gói = 1 datagram.

## Bảng chuẩn / nguồn

| Chuẩn / nguồn | Dùng ở | Ghi chú |
|---------------|--------|---------|
| OpenVPN wire protocol (WIP RFC) | codec | https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html |
| OpenVPN network protocol (doxygen) | reliability (phase sau) | https://build.openvpn.net/doxygen/network_protocol.html |

## Trạng thái & ghi chú

- **Thuần client**, thuần protocol: không I/O, không server. Đọc spec/behavior từ nguồn OpenVPN (**không copy GPL source**).
- Build xanh cả `netstandard2.0` + `net8.0`. Codec dùng `System.Buffers.Binary.BinaryPrimitives` (có ở cả 2 TFM qua `System.Memory`), Span trong method non-async (an toàn C# 12).
- Lộ trình V.2 đầy đủ ở [`.docs/11`](../../.docs/11-todo-roadmap.md) §V.2; thiết kế ở [`.docs/06-openvpn.md`](../../.docs/06-openvpn.md).
