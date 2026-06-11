# TqkLibrary.Vpn.Ethernet

> Tầng L2 Ethernet userspace — codec khung Ethernet II ([EthernetFrame.cs](EthernetFrame.cs)) + địa chỉ MAC 48-bit ([MacAddress.cs](MacAddress.cs)) + **switch học MAC** in-memory ([EthernetSwitch.cs](EthernetSwitch.cs)). **Nền (phase L2.0–L2.1)** để dựng `EthernetAdapter` = switch + virtual host + ARP/NDISC/DHCP ở các phase sau.

## Mục đích

Project này là **nền tầng L2** cho mô phỏng LAN ảo userspace (xem design [03-multihost-l2-vs-l3.md](../../.docs/03-multihost-l2-vs-l3.md) / [09-userspace-ipstack.md](../../.docs/09-userspace-ipstack.md)). Đã có **L2.0** (codec không-phụ-thuộc) + **L2.1** (switch học MAC); các phase L2.2→L2.9 cắm lên:

- **Codec khung Ethernet II** (`dst MAC | src MAC | EtherType | payload`) — đối xứng cách project anh em `TqkLibrary.Vpn.IpStack` cung cấp codec `Ipv4`/`Ipv6`.
- **Kiểu địa chỉ MAC** (`MacAddress`) — value type 48-bit, đóng vai trò khoá FDB của switch (L2.1) và khoá neighbor cache (L2.3/L2.4).
- **`EthernetSwitch`** (L2.1) — switch phần mềm in-memory học `source MAC → port` (FDB) và forward theo dest MAC (unicast đã học đi 1 port; broadcast/multicast/unknown-unicast flood) — là "fabric" để L2.2 cắm N `VirtualHost`.
- **Quy tắc vàng** (design [00 §5](../../.docs/00-architecture-overview.md)): stack TCP/IP **chỉ** bind `IPacketChannel`, không bao giờ thấy Ethernet; mọi MAC/ARP/DHCP nằm ở tầng này. Vì vậy 2 *slot* `INeighborResolver` (ARP/NDISC) + `IAddressConfigurator` (DHCP/SLAAC) được khai báo trong `TqkLibrary.Vpn.Abstractions` (dùng raw bytes/`IPAddress`, **không** ref `MacAddress`) — mới khai báo, hiện thực ở L2.3→L2.6.

## Vị trí trong kiến trúc

- **Tầng:** L2 (Ethernet) — nằm **dưới** `EthernetAdapter` tương lai; bắc cầu xuống `IPacketChannel` cho stack IP đã có.
- **Target frameworks:** `netstandard2.0; net8.0` (xem [src/Directory.Build.props](../Directory.Build.props)); tránh `record`/`init` vì netstandard2.0 thiếu `IsExternalInit` (`MacAddress` là `readonly struct` thường).
- **Phụ thuộc:**
  - ProjectReference: `TqkLibrary.Vpn.Abstractions` (chỉ để gần các slot interface L2 + `IEthernetChannel`; codec hiện chưa dùng type nào của Abstractions — giữ ref cho các phase sau).
  - PackageReference (đặc thù): không có.
- **Được dùng bởi:** chưa có driver/adapter production (mới có test). `EthernetSwitch` (L2.1) đã ở src, sẽ được `EthernetAdapter` (L2.7) compose; các phase sau: `VirtualHost` (L2.2), resolver ARP/NDISC (L2.3/L2.4), configurator DHCP/SLAAC (L2.5/L2.6).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Ethernet/
├── MacAddress.cs            # readonly struct 48-bit (ulong-backed): parse/format, cờ broadcast/multicast/ipv6-mcast, FDB key
├── EthernetFrame.cs         # static codec Ethernet II 14 byte: Build + readers (Destination/Source/EtherType/Payload)
├── EthernetSwitch.cs        # switch học MAC in-memory: FDB (MAC→port) + forward unicast/flood; ConnectHost → IEthernetChannel
└── EthernetSwitch.Port.cs   # partial: nested Port (private) = IEthernetChannel host-facing của switch
```

> Slot interface của tầng này **không** ở đây mà ở `TqkLibrary.Vpn.Abstractions` (tránh phụ thuộc vòng): [INeighborResolver.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/INeighborResolver.cs), [IAddressConfigurator.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IAddressConfigurator.cs); cạnh [IEthernetChannel.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IEthernetChannel.cs).

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `MacAddress` | Địa chỉ MAC 48-bit (lưu `ulong`): `Broadcast`/`Zero`/`FromBytes`, `IsBroadcast`/`IsMulticast`/`IsIpv6Multicast`, `Parse`/`TryParse`/`ToString`, `CopyTo`/`ToArray`, equality + `GetHashCode` (key FDB) | [MacAddress.cs:13](MacAddress.cs#L13) |
| `EthernetFrame` | Codec khung Ethernet II: `Build(dst, src, etherType, payload)` + readers; hằng `HeaderLength=14`, `EtherTypeIpv4/Ipv6/Arp` | [EthernetFrame.cs:8](EthernetFrame.cs#L8) |
| `EthernetSwitch` | Switch học MAC in-memory (`IAsyncDisposable`): `ConnectHost(MacAddress)→IEthernetChannel`, `PortCount`; FDB `Dictionary<MacAddress,Port>`, forward unicast-đã-học / flood broadcast·multicast·unknown-unicast, MAC-move + disconnect purge FDB | [EthernetSwitch.cs:16](EthernetSwitch.cs#L16) |
| `EthernetSwitch.Port` | (nested **private**) port = `IEthernetChannel` host-facing: `WriteFrameAsync`→ingress, `InboundFrame`←egress, props L2 (`Medium=Ethernet`/`MaxHeaderLength=14`/`RequiresLinkAddressResolution`) | [EthernetSwitch.Port.cs:14](EthernetSwitch.Port.cs#L14) |

### Slot interface (khai báo ở Abstractions)

| Type | Vai trò | Hiện thực ở phase | Vị trí |
|------|---------|-------------------|--------|
| `INeighborResolver` | Resolve next-hop IP → MAC (raw 6 byte) | ARP (L2.3) / NDISC (L2.4) | [INeighborResolver.cs:12](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/INeighborResolver.cs#L12) |
| `IAddressConfigurator` | Cấp IP/DNS/route (trả `TunnelConfig`) | DHCPv4 (L2.5) / SLAAC+DHCPv6 (L2.6) | [IAddressConfigurator.cs:14](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IAddressConfigurator.cs#L14) |

## Chuẩn / RFC tuân thủ

| Chuẩn | Type áp dụng | Vị trí (link code) | Ghi chú |
|-------|--------------|--------------------|---------|
| Ethernet II / DIX (khung `dst|src|type|payload`) | `EthernetFrame` | [EthernetFrame.cs:8](EthernetFrame.cs#L8) | Header 14 byte; EtherType ≥ 0x0600 phân biệt với độ dài 802.3 |
| IEEE 802 (MAC-48, bit I/G & U/L) | `MacAddress` | [MacAddress.cs:24](MacAddress.cs#L24) | `IsMulticast` = bit thấp octet 0 (I/G) |
| IEEE 802.3 EtherType assignments | `EthernetFrame.EtherType*` | [EthernetFrame.cs:13-22](EthernetFrame.cs#L13-L22) | IPv4 `0x0800`, IPv6 `0x86DD`, ARP `0x0806` |
| RFC 2464 §7 (IPv6-over-Ethernet, MAC multicast `33:33`) | `MacAddress.IsIpv6Multicast` | [MacAddress.cs:36](MacAddress.cs#L36) | Prefix `33:33` map từ IPv6 multicast |
| IEEE 802.1D §7 (transparent bridging / learning) | `EthernetSwitch` | [EthernetSwitch.cs:16](EthernetSwitch.cs#L16) | Học src-MAC→port + forward/flood; **không** STP, **không** aging |

## API / cách dùng

```csharp
using TqkLibrary.Vpn.Ethernet;

// 1) MAC: parse / format / cờ
MacAddress dst = MacAddress.Broadcast;                 // ff:ff:ff:ff:ff:ff
MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
bool bcast = dst.IsBroadcast;                           // true
bool v6mc  = MacAddress.Parse("33:33:00:00:00:01").IsIpv6Multicast; // true

// 2) Dựng khung Ethernet II bọc một gói IP
byte[] frame = EthernetFrame.Build(dst, src, EthernetFrame.EtherTypeIpv4, ipPacket);

// 3) Đọc khung nhận về
MacAddress to    = EthernetFrame.Destination(frame);
ushort etherType = EthernetFrame.EtherType(frame);
ReadOnlyMemory<byte> payload = EthernetFrame.Payload(frame);

// 4) Switch học MAC: mỗi host nhận một IEthernetChannel làm port
await using var sw = new EthernetSwitch();
IEthernetChannel portA = sw.ConnectHost(MacAddress.Parse("02:00:00:00:00:0a"));
IEthernetChannel portB = sw.ConnectHost(MacAddress.Parse("02:00:00:00:00:0b"));
portB.InboundFrame += f => { /* host B nhận khung switch forward tới */ };
await portA.WriteFrameAsync(frame);   // switch học src của A, rồi forward/flood theo dst
```

## Luồng nội bộ

- **`MacAddress`** ([MacAddress.cs:13](MacAddress.cs#L13)): sáu octet đóng gói big-endian vào low-48-bit của một `ulong` (octet 0 = byte cao nhất). Equality/hash so trên `ulong` nên rẻ → dùng trực tiếp làm khoá `Dictionary` cho FDB switch (L2.1). `IsMulticast` đọc bit I/G của octet đầu ([:30](MacAddress.cs#L30)); `IsIpv6Multicast` kiểm prefix `33:33` ([:36](MacAddress.cs#L36)). `TryParse` ([:81](MacAddress.cs#L81)) chấp nhận phân tách `:` hoặc `-`, đòi đúng 6 octet hex 2 chữ số.
- **`EthernetFrame.Build`** ([EthernetFrame.cs:25](EthernetFrame.cs#L25)): cấp `byte[14 + payload]`, ghi dst/src MAC qua `MacAddress.CopyTo`, EtherType big-endian (byte 12-13), rồi copy payload — đối xứng `Ipv4.Build`. Readers ([:38-50](EthernetFrame.cs#L38-L50)) đọc trực tiếp từ `ReadOnlySpan<byte>`/`ReadOnlyMemory<byte>` không cấp phát (trừ `MacAddress.FromBytes`).
- **`EthernetSwitch.OnIngress`** ([EthernetSwitch.cs:51](EthernetSwitch.cs#L51)): mỗi frame host gửi vào (`Port.WriteFrameAsync`) được switch (a) **học** `_fdb[srcMAC] = ingressPort` (MAC-move tự ghi đè), rồi (b) **chọn đích dưới `_sync`**: dst là multicast (gồm broadcast) **hoặc** unicast chưa-học → gom danh sách flood (mọi port ≠ ingress); unicast đã-học & port ≠ ingress → đúng 1 port; unicast đã-học & port == ingress → drop (không phản xạ). (c) **Deliver ngoài lock** (`Port.Deliver` → raise `InboundFrame`) để handler host có thể ghi lại đồng bộ mà không deadlock. `RemovePort` ([:84](EthernetSwitch.cs#L84)) khi disconnect gỡ port khỏi `_ports` + xoá mọi FDB entry trỏ tới nó (đích cũ thành unknown → flood lại).

## Trạng thái & ghi chú

- **Đã hiện thực (L2.0):** `MacAddress`, `EthernetFrame`, và 2 slot interface (`INeighborResolver`/`IAddressConfigurator` ở Abstractions).
- **Đã hiện thực (L2.1):** `EthernetSwitch` (+ nested `Port`) — switch học MAC in-memory, là src type thật đầu tiên. Test offline: [tests/TqkLibrary.Vpn.Ethernet.Tests/](../../tests/TqkLibrary.Vpn.Ethernet.Tests) (MacAddress + EthernetFrame + in-memory channel pair + **EthernetSwitch**: unknown-unicast/broadcast/ipv6-mcast flood, learned-unicast directed, no-reflect, MAC-move relearn, disconnect purge FDB) — **30 test**.
- **In-memory `IEthernetChannel`**: bản host-facing thật nay là `EthernetSwitch.Port` (private, trong src). Bản đứng-một-mình `EthernetLoopbackPair` (trong [InMemoryEthernetChannelTests.cs](../../tests/TqkLibrary.Vpn.Ethernet.Tests/InMemoryEthernetChannelTests.cs)) vẫn là **test helper** cho test channel L2.0.
- **Cố ý lược bỏ codec** (tối giản, ghi rõ trong [EthernetFrame.cs:3-6](EthernetFrame.cs#L3-L6)):
  - **VLAN 802.1Q tag** (4 byte chèn sau src MAC) — chưa cần cho LAN phẳng.
  - **FCS** (4 byte CRC cuối khung) — NIC/driver phần cứng tự thêm; fabric phần mềm không kiểm.
  - **Padding tối thiểu 60 byte** — chỉ cần trên dây vật lý; switch phần mềm bỏ qua.
- **Cố ý lược bỏ switch** ([EthernetSwitch.cs:11-14](EthernetSwitch.cs#L11-L14)): **FDB aging/timeout** (entry sống tới khi disconnect/MAC-move), **STP** (giả định topo không vòng), **VLAN**, **IGMP/MLD snooping** (mọi multicast đều flood — chưa lọc nhóm).
- **Chưa làm (phase sau):** L2.2 `VirtualHost` + per-host `IPacketChannel` · L2.3 ARP · L2.4 NDISC · L2.5 DHCPv4 · L2.6 SLAAC/DHCPv6 · L2.7 `EthernetAdapter` ráp · L2.8 capabilities/multi-host session · L2.9 test+docs tổng. Xem roadmap [11-todo-roadmap.md §P3](../../.docs/11-todo-roadmap.md).
- Tài liệu as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
