# TqkLibrary.Vpn.Ethernet

> Tầng L2 Ethernet userspace — codec khung Ethernet II ([EthernetFrame.cs](EthernetFrame.cs)) + địa chỉ MAC 48-bit ([MacAddress.cs](MacAddress.cs)) + **switch học MAC** in-memory ([EthernetSwitch.cs](EthernetSwitch.cs)) + **`VirtualHost` cầu nối L2↔L3** ([VirtualHost.cs](VirtualHost.cs)). **Nền (phase L2.0–L2.2)** để dựng `EthernetAdapter` = switch + virtual host + ARP/NDISC/DHCP ở các phase sau.

## Mục đích

Project này là **nền tầng L2** cho mô phỏng LAN ảo userspace (xem design [03-multihost-l2-vs-l3.md](../../.docs/03-multihost-l2-vs-l3.md) / [09-userspace-ipstack.md](../../.docs/09-userspace-ipstack.md)). Đã có **L2.0** (codec không-phụ-thuộc) + **L2.1** (switch học MAC) + **L2.2** (`VirtualHost` cầu nối L2↔L3); các phase L2.3→L2.9 cắm lên:

- **Codec khung Ethernet II** (`dst MAC | src MAC | EtherType | payload`) — đối xứng cách project anh em `TqkLibrary.Vpn.IpStack` cung cấp codec `Ipv4`/`Ipv6`.
- **Kiểu địa chỉ MAC** (`MacAddress`) — value type 48-bit, đóng vai trò khoá FDB của switch (L2.1) và khoá neighbor cache (L2.3/L2.4).
- **`EthernetSwitch`** (L2.1) — switch phần mềm in-memory học `source MAC → port` (FDB) và forward theo dest MAC (unicast đã học đi 1 port; broadcast/multicast/unknown-unicast flood) — là "fabric" để cắm N `VirtualHost`.
- **`VirtualHost`** (L2.2) — mỗi "máy ảo" trên LAN = {MAC, port switch, resolver}, **expose một `IPacketChannel`** cho `TcpIpStack` đã có (dual-stack v4/v6): egress bọc gói IP vào khung Ethernet (resolve dest-MAC qua `INeighborResolver`) → switch; ingress tháo khung → gói IP cho stack. Đây là nơi **quy tắc vàng** thành hiện thực — stack chỉ thấy `IPacketChannel`.
- **Quy tắc vàng** (design [00 §5](../../.docs/00-architecture-overview.md)): stack TCP/IP **chỉ** bind `IPacketChannel`, không bao giờ thấy Ethernet; mọi MAC/ARP/DHCP nằm ở tầng này. Vì vậy 2 *slot* `INeighborResolver` (ARP/NDISC) + `IAddressConfigurator` (DHCP/SLAAC) được khai báo trong `TqkLibrary.Vpn.Abstractions` (dùng raw bytes/`IPAddress`, **không** ref `MacAddress`) — mới khai báo, hiện thực ở L2.3→L2.6.

## Vị trí trong kiến trúc

- **Tầng:** L2 (Ethernet) — nằm **dưới** `EthernetAdapter` tương lai; bắc cầu xuống `IPacketChannel` cho stack IP đã có.
- **Target frameworks:** `netstandard2.0; net8.0` (xem [src/Directory.Build.props](../Directory.Build.props)); tránh `record`/`init` vì netstandard2.0 thiếu `IsExternalInit` (`MacAddress` là `readonly struct` thường).
- **Phụ thuộc:**
  - ProjectReference: **chỉ** `TqkLibrary.Vpn.Abstractions` (slot L2 `INeighborResolver`/`IAddressConfigurator` + `IEthernetChannel`/`IPacketChannel`/`LinkMedium` mà `VirtualHost` hiện thực/tiêu thụ). **Cố ý KHÔNG** ref `TqkLibrary.Vpn.IpStack` dù `VirtualHost` cần đọc version-nibble + IP đích — đó là **phụ thuộc ngang** mà layering cấm ([10 §2](../../.docs/10-codebase-architecture-and-flow.md)), nên đọc thẳng từ offset header cố định (RFC 791/8200).
  - PackageReference (đặc thù): không có.
- **Được dùng bởi:** chưa có driver/adapter production (mới có test). `EthernetSwitch` (L2.1) + `VirtualHost` (L2.2) đã ở src; `VirtualHost` được một `TcpIpStack` bind (`new TcpIpStack(virtualHost, ip)`) và sẽ được `EthernetAdapter` (L2.7) compose; các phase sau: resolver ARP/NDISC (L2.3/L2.4), configurator DHCP/SLAAC (L2.5/L2.6).

## Cấu trúc thư mục

```
TqkLibrary.Vpn.Ethernet/
├── MacAddress.cs            # readonly struct 48-bit (ulong-backed): parse/format, cờ broadcast/multicast/ipv6-mcast, FDB key
├── EthernetFrame.cs         # static codec Ethernet II 14 byte: Build + readers (Destination/Source/EtherType/Payload)
├── EthernetSwitch.cs        # switch học MAC in-memory: FDB (MAC→port) + forward unicast/flood; ConnectHost → IEthernetChannel
├── EthernetSwitch.Port.cs   # partial: nested Port (private) = IEthernetChannel host-facing của switch
└── VirtualHost.cs           # cầu nối L2↔L3 (: IPacketChannel): wrap/strip Ethernet cho TcpIpStack, resolve dest-MAC qua INeighborResolver
```

> Slot interface của tầng này **không** ở đây mà ở `TqkLibrary.Vpn.Abstractions` (tránh phụ thuộc vòng): [INeighborResolver.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/INeighborResolver.cs), [IAddressConfigurator.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IAddressConfigurator.cs); cạnh [IEthernetChannel.cs](../TqkLibrary.Vpn.Abstractions/Channels/Interfaces/IEthernetChannel.cs).

## Thành phần chính

| Type | Vai trò | Vị trí |
|------|---------|--------|
| `MacAddress` | Địa chỉ MAC 48-bit (lưu `ulong`): `Broadcast`/`Zero`/`FromBytes`, `IsBroadcast`/`IsMulticast`/`IsIpv6Multicast`, `Parse`/`TryParse`/`ToString`, `CopyTo`/`ToArray`, equality + `GetHashCode` (key FDB) | [MacAddress.cs:13](MacAddress.cs#L13) |
| `EthernetFrame` | Codec khung Ethernet II: `Build(dst, src, etherType, payload)` + readers; hằng `HeaderLength=14`, `EtherTypeIpv4/Ipv6/Arp` | [EthernetFrame.cs:8](EthernetFrame.cs#L8) |
| `EthernetSwitch` | Switch học MAC in-memory (`IAsyncDisposable`): `ConnectHost(MacAddress)→IEthernetChannel`, `PortCount`; FDB `Dictionary<MacAddress,Port>`, forward unicast-đã-học / flood broadcast·multicast·unknown-unicast, MAC-move + disconnect purge FDB | [EthernetSwitch.cs:16](EthernetSwitch.cs#L16) |
| `EthernetSwitch.Port` | (nested **private**) port = `IEthernetChannel` host-facing: `WriteFrameAsync`→ingress, `InboundFrame`←egress, props L2 (`Medium=Ethernet`/`MaxHeaderLength=14`/`RequiresLinkAddressResolution`) | [EthernetSwitch.Port.cs:14](EthernetSwitch.Port.cs#L14) |
| `VirtualHost` | Cầu nối L2↔L3 (`: IPacketChannel`): giữ MAC + port switch + `INeighborResolver`; egress wrap Ethernet (resolve dest-MAC) → switch, ingress strip → `InboundIpPacket` (non-IP/ARP → `InboundNonIpFrame`); `Mtu=link−14`, `Medium=Ip` | [VirtualHost.cs:23](VirtualHost.cs#L23) |

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
| Design 00 §5 (quy tắc vàng: stack chỉ bind `IPacketChannel`) | `VirtualHost` | [VirtualHost.cs:23](VirtualHost.cs#L23) | Ẩn toàn bộ Ethernet/MAC khỏi `TcpIpStack` |
| RFC 791 §3.1 / RFC 8200 §3 (offset header IPv4/IPv6) | `VirtualHost` (egress đọc version + dst) | [VirtualHost.cs:76](VirtualHost.cs#L76) | Đọc version-nibble + IP đích bằng offset cố định (16/24), **không** ref project IpStack |

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

// 5) VirtualHost: một "máy ảo" trên LAN — expose IPacketChannel cho TcpIpStack
//    (resolver là slot ARP/NDISC, hiện thực ở L2.3/L2.4; ở đây minh hoạ bằng impl bất kỳ)
INeighborResolver resolver = /* ARP/NDISC, hoặc map IP→MAC */ default!;
await using var hostA = new VirtualHost(MacAddress.Parse("02:00:00:00:00:0a"), sw.ConnectHost(MacAddress.Parse("02:00:00:00:00:0a")), resolver);
var stack = new TcpIpStack(hostA, IPAddress.Parse("10.0.0.10"));   // stack chỉ thấy IPacketChannel — không biết Ethernet
// stack.ConnectAsync(...) → VirtualHost tự bọc Ethernet + resolve dest-MAC, đẩy qua switch
```

## Luồng nội bộ

- **`MacAddress`** ([MacAddress.cs:13](MacAddress.cs#L13)): sáu octet đóng gói big-endian vào low-48-bit của một `ulong` (octet 0 = byte cao nhất). Equality/hash so trên `ulong` nên rẻ → dùng trực tiếp làm khoá `Dictionary` cho FDB switch (L2.1). `IsMulticast` đọc bit I/G của octet đầu ([:30](MacAddress.cs#L30)); `IsIpv6Multicast` kiểm prefix `33:33` ([:36](MacAddress.cs#L36)). `TryParse` ([:81](MacAddress.cs#L81)) chấp nhận phân tách `:` hoặc `-`, đòi đúng 6 octet hex 2 chữ số.
- **`EthernetFrame.Build`** ([EthernetFrame.cs:25](EthernetFrame.cs#L25)): cấp `byte[14 + payload]`, ghi dst/src MAC qua `MacAddress.CopyTo`, EtherType big-endian (byte 12-13), rồi copy payload — đối xứng `Ipv4.Build`. Readers ([:38-50](EthernetFrame.cs#L38-L50)) đọc trực tiếp từ `ReadOnlySpan<byte>`/`ReadOnlyMemory<byte>` không cấp phát (trừ `MacAddress.FromBytes`).
- **`EthernetSwitch.OnIngress`** ([EthernetSwitch.cs:51](EthernetSwitch.cs#L51)): mỗi frame host gửi vào (`Port.WriteFrameAsync`) được switch (a) **học** `_fdb[srcMAC] = ingressPort` (MAC-move tự ghi đè), rồi (b) **chọn đích dưới `_sync`**: dst là multicast (gồm broadcast) **hoặc** unicast chưa-học → gom danh sách flood (mọi port ≠ ingress); unicast đã-học & port ≠ ingress → đúng 1 port; unicast đã-học & port == ingress → drop (không phản xạ). (c) **Deliver ngoài lock** (`Port.Deliver` → raise `InboundFrame`) để handler host có thể ghi lại đồng bộ mà không deadlock. `RemovePort` ([:84](EthernetSwitch.cs#L84)) khi disconnect gỡ port khỏi `_ports` + xoá mọi FDB entry trỏ tới nó (đích cũ thành unknown → flood lại).
- **`VirtualHost`** ([VirtualHost.cs:23](VirtualHost.cs#L23)): object **là** `IPacketChannel` mà `TcpIpStack` bind, đồng thời giữ MAC + port switch + resolver. **Egress** ([`WriteIpPacketAsync` @ :69](VirtualHost.cs#L69)): đọc version-nibble (`packet[0]>>4`) chọn EtherType + trích IP đích từ offset cố định (v4 @16, v6 @24 — không ref `IpStack` để giữ no-horizontal-dep), `await resolver.ResolveAsync(dstIp)` lấy MAC (on-link: next-hop = IP đích; `null` → drop), `EthernetFrame.Build` → `port.WriteFrameAsync`. **Ingress** ([`OnInboundFrame` @ :106](VirtualHost.cs#L106)) đăng ký `port.InboundFrame`: khung < 14 byte → drop; EtherType IPv4/IPv6 → `InboundIpPacket?.Invoke(Payload)` (slice zero-copy, valid trong handler vì switch raise đồng bộ); khác (ARP) → `InboundNonIpFrame?.Invoke(frame)` (seam cho L2.3). `Mtu=link−14` tính 1 lần trong ctor; `DisposeAsync` unsubscribe + null event + `port.DisposeAsync()` (gỡ khỏi switch).

## Trạng thái & ghi chú

- **Đã hiện thực (L2.0):** `MacAddress`, `EthernetFrame`, và 2 slot interface (`INeighborResolver`/`IAddressConfigurator` ở Abstractions).
- **Đã hiện thực (L2.1):** `EthernetSwitch` (+ nested `Port`) — switch học MAC in-memory, là src type thật đầu tiên.
- **Đã hiện thực (L2.2):** [`VirtualHost`](VirtualHost.cs#L23) (`: IPacketChannel`) — cầu nối L2↔L3 expose `IPacketChannel` cho `TcpIpStack` (wrap/strip Ethernet, resolve dest-MAC qua `INeighborResolver`, MTU=link−14). Hiện thực **quy tắc vàng**: stack không bao giờ thấy Ethernet.
- **Test offline (L2.0–L2.2):** [tests/TqkLibrary.Vpn.Ethernet.Tests/](../../tests/TqkLibrary.Vpn.Ethernet.Tests) — MacAddress + EthernetFrame + in-memory channel pair + **EthernetSwitch** (unknown-unicast/broadcast/ipv6-mcast flood, learned-unicast directed, no-reflect, MAC-move relearn, disconnect purge FDB) + **VirtualHost** ([VirtualHostTests.cs](../../tests/TqkLibrary.Vpn.Ethernet.Tests/VirtualHostTests.cs): egress wrap v4/v6 + unresolved/non-IP drop, ingress strip v4/v6 + ARP→non-IP-hook + runt-ignore, link-props, tích hợp 2-host qua switch, dispose-detach) — **41 test**.
- **In-memory `IEthernetChannel`**: bản host-facing thật nay là `EthernetSwitch.Port` (private, trong src). Bản đứng-một-mình `EthernetLoopbackPair` (trong [InMemoryEthernetChannelTests.cs](../../tests/TqkLibrary.Vpn.Ethernet.Tests/InMemoryEthernetChannelTests.cs)) vẫn là **test helper** cho test channel L2.0.
- **⚠️ "LAN ảo" này hiện là fabric LOCAL in-process, CHƯA nối VPN.** Mục tiêu thiết kê ([03](../../.docs/03-multihost-l2-vs-l3.md)): LAN ảo = **broadcast domain do L2 VPN server cấp** (SoftEther bridge / OpenVPN-tap) — client mở **1 kết nối VPN** nhận khung Ethernet thật, rồi đặt **N `VirtualHost`** (mỗi MAC+IP riêng, ARP/DHCP do **server** trả lời) lên đó. Nhưng tới L2.2 mới có **switch in-memory + VirtualHost nói chuyện với nhau trong tiến trình** — **chưa có driver L2 nào sinh `IEthernetChannel` thật từ kết nối VPN** (uplink). Vì vậy hiện chạy như một LAN ảo **local/mô phỏng** (test offline + làm nền). **Driver L2 thật** (SoftEther/tap) là **item P3 riêng** (roadmap §P3 "Ghi chú phụ thuộc") — khi có, uplink VPN cắm vào switch như một port nữa → các VirtualHost local thông ra LAN thật của VPN.
- **Cố ý lược bỏ codec** (tối giản, ghi rõ trong [EthernetFrame.cs:3-6](EthernetFrame.cs#L3-L6)):
  - **VLAN 802.1Q tag** (4 byte chèn sau src MAC) — chưa cần cho LAN phẳng.
  - **FCS** (4 byte CRC cuối khung) — NIC/driver phần cứng tự thêm; fabric phần mềm không kiểm.
  - **Padding tối thiểu 60 byte** — chỉ cần trên dây vật lý; switch phần mềm bỏ qua.
- **Cố ý lược bỏ switch** ([EthernetSwitch.cs:11-14](EthernetSwitch.cs#L11-L14)): **FDB aging/timeout** (entry sống tới khi disconnect/MAC-move), **STP** (giả định topo không vòng), **VLAN**, **IGMP/MLD snooping** (mọi multicast đều flood — chưa lọc nhóm).
- **Cố ý lược bỏ VirtualHost** ([VirtualHost.cs:17-21](VirtualHost.cs#L17-L21)): **routing/gateway** (next-hop = IP đích, giả định on-link — chưa chọn gateway cho đích off-link); **read-loop/Pipe per-host** (design `09` đặt mục tiêu 1 read-loop + backpressure, nhưng hiện event-driven callback như phần data plane còn lại — để mục P2 hiệu năng); **không** ref project `IpStack` (đọc header L3 bằng offset cố định để tránh phụ thuộc ngang).
- **Chưa làm (phase sau):** L2.3 ARP · L2.4 NDISC · L2.5 DHCPv4 · L2.6 SLAAC/DHCPv6 · L2.7 `EthernetAdapter` ráp · L2.8 capabilities/multi-host session · L2.9 test+docs tổng · **driver L2 thật** (SoftEther/tap → uplink VPN). Xem roadmap [11-todo-roadmap.md §P3](../../.docs/11-todo-roadmap.md).
- Tài liệu as-built tổng thể: [10-codebase-architecture-and-flow.md](../../.docs/10-codebase-architecture-and-flow.md).
