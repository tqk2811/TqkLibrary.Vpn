# 00 — Kiến trúc tổng quan

> Nền tảng plugin VPN chạy userspace, expose API Socket-like (`VpnTcpClient`/`VpnUdpClient`).
> Mọi giao thức hội tụ về một "đường ống gói IP" (`IPacketChannel`). Tài liệu này là bản đồ tầng.

> **[As-built]** File này là **design-intent**; vài chỗ đã lệch khỏi code thật (xem chi tiết ở
> [`10-codebase-architecture-and-flow.md`](10-codebase-architecture-and-flow.md) §"Khác biệt so với design docs").
> Tóm tắt lệch: tên interface thật là `IVpnConnection`/`IVpnSession` (không phải `VpnConnection`/`VpnSession`)
> và `ConnectAsync` **không có** tham số `options`; `IVpnTransport` tách thành `IByteStreamTransport`/`IDatagramTransport`;
> decorator `EspIkeDemuxTransport` **không tồn tại** (demux IKE/ESP nằm trong `NatTraversalChannel`);
> hai hợp đồng `ISecuritySession`/`IPacketEncapsulator` **đã xóa** (P0.1) — sẽ tái thiết kế từ ≥2 consumer thật (roadmap F.2);
> nền L2 (`EthernetAdapter`/`VirtualHost`/multi-host) **đã hiện thực đầy đủ** (phase L2.0–L2.9).

## Nguyên tắc cốt lõi

Mọi thứ dưới tầng IP chỉ là **cách vận chuyển gói IP**; mọi thứ trên tầng IP đều dùng chung. Hai ranh giới trừu tượng cho phép mọi driver cắm vào cùng một stack:

- **`IPacketChannel`** (L3): đọc/ghi **gói IPv4/IPv6 thô**. Stack TCP/IP chỉ thấy interface này.
- **`IEthernetChannel`** (L2): đọc/ghi **khung Ethernet**. Chỉ giao thức L2 dùng; được `EthernetAdapter` bắc cầu xuống `IPacketChannel`.

## Sơ đồ phân tầng

```
        VpnTcpClient / VpnUdpClient / VpnStream            [CHUNG - Sockets]
                         │
        Userspace TCP/IP stack (TCP SM, UDP, ICMP, IPv4)   [CHUNG - chỉ thấy IPacketChannel]
                         │  IPacketChannel (L3, gói IP thô)
        ┌────────────────┴───────────────────────────┐
   (L3 drivers cắm thẳng)                    EthernetAdapter (L2→L3)
                                              = EthernetSwitch (MAC-learning FDB + broadcast)
                                                + N × VirtualHost{MAC, ARP, DHCP-client, IPacketChannel}
                         │ IEthernetChannel (L2, khung Ethernet)
   ┌─────────────────────┬──────────────────────┬─────────────────────┐
 PPP-based            OpenVPN-tun           SoftEther / OpenVPN-tap   VXLAN/L2overlay
 (L2TP, SSTP)         (IP trực tiếp)        (Ethernet over HTTPS)     (tương lai)
```

## Hợp đồng plugin: driver = tổ hợp 4 abstraction ghép được

| # | Abstraction | Triển khai |
|---|-------------|-----------|
| 1 | **`IVpnTransport`** | `IByteStreamTransport` (TCP/TLS) hoặc `IDatagramTransport` (UDP). Decorator `EspIkeDemuxTransport` tách non-zero-SPI vs Non-ESP-Marker trên cổng 4500 (RFC 3948). |
| 2 | **`ISecuritySession`** | `Protect/Unprotect/Handshake`. Cài: `TlsSecurity`, `EspSecurity`, `NoiseSecurity`, `MppeSecurity`, `NullSecurity`. |
| 3 | **`IPacketEncapsulator`** | `LengthPrefix`, `HdlcAsync`, `FixedHeader<T>`, `Tlv`. |
| 4 | **Output (link-layer pivot)** | đúng 1 trong: `IPacketChannel` (L3) hoặc `IEthernetChannel` (L2). |

> **[As-built]** Bảng 4-abstraction trên là design-intent. Thực tế (xem [`10`](10-codebase-architecture-and-flow.md)
> §"Khác biệt"): (1) `IVpnTransport` → tách `IByteStreamTransport`/`IDatagramTransport`, **không có** `EspIkeDemuxTransport`
> (demux trong [`NatTraversalChannel`](../src/TqkLibrary.VpnClient.Ipsec/Nat/NatTraversalChannel.cs#L13)); (2)+(3) `ISecuritySession`
> + `IPacketEncapsulator` **đã xóa ở P0.1** — shape thật phân kỳ (`EspSession` dùng `TryUnprotect` bool; framing là HDLC/
> `L2tpCodec`/SSTP-4-byte/opcode-OpenVPN riêng từng driver) — tái thiết kế từ ≥2 consumer thật ở roadmap F.2.

`IVpnProtocolDriver` = entry point: `VpnDriverCapabilities Capabilities` + `Task<IVpnSession> ConnectAsync(endpoint, credentials, options, ct)`.

> **[As-built]** Tên thật là `IVpnProtocolDriver.ConnectAsync(endpoint, credentials, ct)` — **không có** tham số `options`;
> consumer dùng `IVpnConnection`/`IVpnSession` (không phải `VpnConnection`/`VpnSession`).

`VpnDriverCapabilities` khai báo: `LinkLayer` (L3Ip|L2Ethernet|Both), `SupportsMultiHost`, `MultiHostModel` (None|RoutedPrefixes|L2BroadcastDomain), `UsesPpp`, `TransportKinds`, `SecurityKinds`, `AuthMethods`, `AddressAssignment` (Ipcp|ConfigPush|OutOfBand|Dhcp), `RequiresRawIpSocket`, `RequiresElevation`.

## Quy tắc vàng (theo tiền lệ gVisor/smoltcp — xem `09-userspace-ipstack.md`)

1. **Stack TCP/IP CHỈ bind `IPacketChannel`, không bao giờ thấy Ethernet.** Toàn bộ ARP/MAC/DHCP nằm trong `EthernetAdapter`.
2. `ILinkChannel` base chung: `Mtu`, `MaxHeaderLength`, `Medium` (Ip|Ethernet), `RequiresLinkAddressResolution` (= gVisor `CapabilityResolutionRequired`).
3. L3 driver dùng `PassthroughPacketChannel` (no-op framing, `MaxHeaderLength = 0`).
4. **NAT/DNS là sidecar tuỳ chọn** (`INatTranslator`/`IDnsResolver`), KHÔNG nhồi vào `EthernetAdapter`.
5. `INeighborResolver` (ARP nay, NDISC sau) + `IAddressConfigurator` (DHCPv4 nay, SLAAC/DHCPv6 sau) là slot cắm được.
6. Data path: `System.Threading.Channels`/Pipelines + `ArrayPool`, không alloc mỗi gói.

## Mô hình API phía consumer

```
VpnClient (façade, đăng ký driver)
  └─ VpnConnection  (1 transport / 1 IKE-SA)
       └─ VpnSession (mỗi session = 1 IP = 1 instance IpStack)   ← L2TP có thể 1..N; SSTP luôn 1; L2 = N VirtualHost
            ├─ VpnTcpClient.ConnectAsync(remoteEndPoint)
            └─ VpnUdpClient.Bind() / SendTo / ReceiveFrom
```

Xem chi tiết multi-host ở `03-multihost-l2-vs-l3.md`.

> **[As-built]** Nền L2 (`EthernetSwitch`/`VirtualHost`/`EthernetAdapter`/`MultiHostSession`, phase L2.0–L2.9) **đã hiện thực**
> trong project [`TqkLibrary.VpnClient.Ethernet`](../src/TqkLibrary.VpnClient.Ethernet) và **đã có driver L2 thật** tiêu thụ
> (OpenVPN tap-mode V2.h + SoftEther V4.c — cả hai có chế độ bắc-cầu-1-host và multi-host). Hợp đồng `IEthernetChannel`
> **có impl src** (`EthernetSwitch.Port`). Đường live **L3** (SSTP/L2TP/IKEv2/WireGuard/OpenConnect/OpenVPN-tun) vẫn cắm
> thẳng `IPacketChannel` như sơ đồ. Chi tiết & trạng thái: [`10`](10-codebase-architecture-and-flow.md) §5/§8/§"Khác biệt".
