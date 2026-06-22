# TqkLibrary.VpnClient

> Façade của thư viện: `VpnClient` / `VpnClientBuilder`, đăng ký driver, lắp ráp DI. Đây là tầng cao nhất mà ứng dụng gọi vào.

## Mục đích

Project này là **điểm vào (entry point)** duy nhất của toàn bộ thư viện TqkLibrary.VpnClient — một VPN client thuần userspace, plugin theo driver.

- Cho ứng dụng một API gọn để **đăng ký các protocol driver** (SSTP, L2TP/IPsec, IKEv2, OpenVPN, WireGuard, OpenConnect, SoftEther) theo kiểu fluent rồi **mở kết nối theo tên giao thức**.
- Giấu toàn bộ độ phức tạp của stack bên dưới (IKE/ESP/L2TP/PPP/TLS/Noise/DTLS/IP stack): app chỉ thấy `VpnClient.ConnectAsync(...)` trả về một `IVpnConnection`.
- Là nơi **đảo ngược phụ thuộc** hội tụ: façade biết về các driver cụ thể (`SstpDriver`, `L2tpIpsecDriver`, `Ikev2Driver`, `OpenVpnDriver`, `WireGuardDriver`, `OpenConnectDriver`, `SoftEtherDriver`), còn mọi tầng dưới chỉ phụ thuộc vào abstractions.

Vì sao tồn tại: tách "ai dùng giao thức nào" (ứng dụng) khỏi "giao thức được lắp ráp ra sao" (driver + protocol + crypto). App chỉ cần `TqkLibrary.VpnClient`, không phải tham chiếu trực tiếp tới Ipsec/L2tp/Ppp/OpenVpn/WireGuard/SoftEther/Transport...

## Vị trí trong kiến trúc

- **Tầng:** APP / Façade — đỉnh của đồ thị phụ thuộc, được ứng dụng tiêu thụ tham chiếu.
- **Target frameworks:** `netstandard2.0; net8.0` (kế thừa từ [Directory.Build.props](../Directory.Build.props)). `record`/`init` khả dụng cả 2 TFM nhờ polyfill `TqkLibrary.CompilerServices` (`IsExternalInit`).
- **Phụ thuộc (ProjectReference) — Sockets + 7 project driver:**
  - [TqkLibrary.VpnClient.Sockets](../TqkLibrary.VpnClient.Sockets) — API socket chạy trong tunnel (re-export cho app).
  - [TqkLibrary.VpnClient.Drivers.L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec) — nơi `L2tpIpsecDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) — nơi `Ikev2Driver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) — nơi `OpenConnectDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn) — nơi `OpenVpnDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.Sstp](../TqkLibrary.VpnClient.Drivers.Sstp) — nơi `SstpDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard) — nơi `WireGuardDriver` được khai báo.
  - [TqkLibrary.VpnClient.Drivers.SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther) — nơi `SoftEtherDriver` được khai báo.
  - Không có `PackageReference` đặc thù. Façade **không** ref `Crypto` trực tiếp (2 file `VpnClient`/`VpnClientBuilder` không chạm primitive nào — P0.2); `Crypto` vẫn có trong output theo **transitive** qua Drivers → Ipsec/Ppp/OpenVpn/WireGuard/SoftEther/Transport.Dtls.
- **Được dùng bởi:** ứng dụng tiêu thụ (không project nào khác trong solution ref tới project này).

## Cấu trúc thư mục

```
TqkLibrary.VpnClient/
├── VpnClientBuilder.cs   # Builder fluent: AddDriver / UseSstp / UseL2tpIpsec / UseIkev2 / UseOpenVpn / UseWireGuard / UseOpenConnect / UseSoftEther → Build()
└── VpnClient.cs          # Client đã build: giữ map driver theo tên, ConnectAsync / Protocols / GetCapabilities
```

Project chỉ gồm 2 type — toàn bộ "logic" thực sự nằm ở các project driver/protocol bên dưới.

## Thành phần chính

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `VpnClientBuilder` | Builder fluent: đăng ký driver theo `Name`, có shortcut `UseSstp()`/`UseL2tpIpsec()`/`UseIkev2()`/`UseOpenVpn()`/`UseWireGuard()`/`UseOpenConnect()`/`UseSoftEther()`, kết thúc bằng `Build()` | [VpnClientBuilder.cs:18](VpnClientBuilder.cs#L18) |
| `VpnClientBuilder.AddDriver` | Đăng ký một `IVpnProtocolDriver` bất kỳ (keyed theo `driver.Name`) | [VpnClientBuilder.cs:23](VpnClientBuilder.cs#L23) |
| `VpnClientBuilder.UseSstp` | Đăng ký `SstpDriver` (key `"sstp"`), auto-reconnect bật mặc định; overload nhận `SstpReconnectOptions` và/hoặc `RemoteCertificateValidationCallback` (cert TLS, P0.6 — null ⇒ accept all) | [VpnClientBuilder.cs:30-41](VpnClientBuilder.cs#L30-L41) |
| `VpnClientBuilder.UseL2tpIpsec` | Đăng ký `L2tpIpsecDriver` (key `"l2tp-ipsec"`), auto-reconnect bật mặc định; overload nhận `L2tpIpsecReconnectOptions` và `(reconnect, L2tpIpsecTimeoutOptions)` | [VpnClientBuilder.cs:44-51](VpnClientBuilder.cs#L44-L51) |
| `VpnClientBuilder.UseIkev2` | Đăng ký `Ikev2Driver` (key `"ikev2"`, IKEv2-native RFC 7296 PSK/EAP + ESP tunnel mode), auto-reconnect bật mặc định; overload nhận `Ikev2ReconnectOptions`, và overload `UseIkev2(IkeCertificateTrust, Ikev2ReconnectOptions?)` verify gateway bằng **certificate** (chữ ký số RFC 7296 §2.15) | [VpnClientBuilder.cs:54-67](VpnClientBuilder.cs#L54-L67) |
| `VpnClientBuilder.UseOpenVpn` | Đăng ký `OpenVpnDriver` (key `"openvpn"`) từ một `OpenVpnProfile` đã parse; overload nhận `X509CertificateCollection?` (client cert) + `RemoteCertificateValidationCallback?` (cert server) + `OpenVpnReconnectOptions?` | [VpnClientBuilder.cs:70-75](VpnClientBuilder.cs#L70-L75) |
| `VpnClientBuilder.UseWireGuard` | Đăng ký `WireGuardDriver` (key `"wireguard"`) từ một `WireGuardConfig` tĩnh, auto-reconnect bật mặc định; overload nhận `WireGuardReconnectOptions` | [VpnClientBuilder.cs:78-82](VpnClientBuilder.cs#L78-L82) |
| `VpnClientBuilder.UseOpenConnect` | Đăng ký `OpenConnectDriver` (key `"openconnect"`, Cisco AnyConnect/ocserv: HTTPS config-auth → CSTP, bare IP, DTLS 1.2 data plane fallback TLS), auto-reconnect bật mặc định; overload nhận `OpenConnectReconnectOptions`, và `(reconnect, RemoteCertificateValidationCallback?, groupSelect)` | [VpnClientBuilder.cs:89-101](VpnClientBuilder.cs#L89-L101) |
| `VpnClientBuilder.UseSoftEther` | Đăng ký `SoftEtherDriver` (key `"softether"`, SSL-VPN Ethernet-over-TLS, DHCP-leased, SHA-0 password auth) targeting `hubName`, auto-reconnect bật mặc định; overload nhận `SoftEtherSessionParams`, `(session, SoftEtherReconnectOptions)`, và `(hubName, bool enableIpv6)` | [VpnClientBuilder.cs:107-122](VpnClientBuilder.cs#L107-L122) |
| `VpnClient` | Client đã build: giữ `IReadOnlyDictionary<string, IVpnProtocolDriver>` các driver | [VpnClient.cs:8](VpnClient.cs#L8) |
| `VpnClient.ConnectAsync` | Tra driver theo tên giao thức (qua helper `ResolveDriver`) rồi ủy thác `driver.ConnectAsync(endpoint, credentials, ct)` | [VpnClient.cs:18](VpnClient.cs#L18) |
| `VpnClient.Protocols` | Liệt kê tên các giao thức đã đăng ký | [VpnClient.cs:15](VpnClient.cs#L15) |
| `VpnClient.GetCapabilities` | Trả `VpnDriverCapabilities` của một driver đã đăng ký (qua helper `ResolveDriver`) | [VpnClient.cs:22](VpnClient.cs#L22) |
| `VpnClient.ResolveDriver` | Helper private tra driver theo tên; ném `NotSupportedException` (kèm danh sách protocol đã đăng ký) nếu chưa đăng ký — dùng chung cho `ConnectAsync`+`GetCapabilities` (P0.5) | [VpnClient.cs:25](VpnClient.cs#L25) |

Các hợp đồng/model mà façade thao tác (định nghĩa ở Abstractions):

| Type | Vai trò | Vị trí |
| --- | --- | --- |
| `IVpnProtocolDriver` | Điểm vào plugin của 1 giao thức: `Name`, `Capabilities`, `ConnectAsync` | [IVpnProtocolDriver.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnProtocolDriver.cs#L9) |
| `IVpnConnection` | Kết nối sống (1 IKE-SA / 1 TLS), sở hữu nhiều `IVpnSession`; `IAsyncDisposable` | [IVpnConnection.cs:7](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnConnection.cs#L7) |
| `IVpnSession` | Một endpoint IP logic: `Config` + `PacketChannel` | [IVpnSession.cs:10](../TqkLibrary.VpnClient.Abstractions/Drivers/Interfaces/IVpnSession.cs#L10) |
| `VpnEndpoint` | Địa chỉ server (host + port + `AddressFamilyPreference`) | [VpnEndpoint.cs:6](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnEndpoint.cs#L6) |
| `VpnCredentials` | `Username` / `Password` (MS-CHAPv2) + `PreSharedKey` (IKE PSK) | [VpnCredentials.cs:4](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnCredentials.cs#L4) |
| `VpnDriverCapabilities` | Khả năng driver (link layer, transport, security, auth, elevation...) | [VpnDriverCapabilities.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/VpnDriverCapabilities.cs#L9) |
| `TunnelConfig` | IP/DNS/route/MTU một session nhận được | [TunnelConfig.cs:9](../TqkLibrary.VpnClient.Abstractions/Drivers/Models/TunnelConfig.cs#L9) |

## Chuẩn / RFC tuân thủ

Bản thân project façade **không hiện thực chuẩn mạng nào** — nó chỉ điều phối driver. Các chuẩn dưới đây được **truy cập gián tiếp** qua các shortcut `UseSstp()`/`UseL2tpIpsec()`/`UseIkev2()`/`UseOpenVpn()`/`UseWireGuard()`/`UseOpenConnect()`/`UseSoftEther()`; cột "Vị trí" link tới nơi façade kích hoạt driver tương ứng, và (nếu có) tới class summary ở driver. Project này không có comment `RFC` nào, nên gần như toàn bộ là **(suy luận)** — chi tiết ánh xạ chuẩn → code nằm ở README của các project Drivers/Ipsec/L2tp/Ppp/OpenVpn/WireGuard/SoftEther/Transport.Dtls.

| Chuẩn (RFC/FIPS/NIST/MS-*) | Class/Namespace áp dụng | Vị trí (link code) | Ghi chú |
| --- | --- | --- | --- |
| [MS-SSTP] (Secure Socket Tunneling Protocol) | `SstpDriver` qua `UseSstp()` | [VpnClientBuilder.cs:30-41](VpnClientBuilder.cs#L30-L41), [SstpDriver.cs:9](../TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L9) | Driver mô tả "TLS over 443, PPP, MS-CHAPv2"; cert TLS validate qua callback tùy chọn (P0.6) |
| RFC 2759 (MS-CHAPv2) | `SstpDriver` + `L2tpIpsecDriver` (PPP auth) | [VpnClientBuilder.cs:30](VpnClientBuilder.cs#L30), [VpnClientBuilder.cs:44](VpnClientBuilder.cs#L44) | (suy luận) — codec ở Crypto/`MsChapV2`, framing CHAP ở Ppp/`MsChapV2Authenticator` |
| RFC 2409 (IKEv1 / ISAKMP) | `L2tpIpsecDriver` qua `UseL2tpIpsec()` | [VpnClientBuilder.cs:44-51](VpnClientBuilder.cs#L44-L51), [L2tpIpsecDriver.cs:9](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L9) | (suy luận) — comment driver "IKEv1 PSK over NAT-T"; logic ở Ipsec `Ike/V1` |
| RFC 7296 (IKEv2) + ESP tunnel mode + CP | `Ikev2Driver` qua `UseIkev2()` / `UseIkev2(IkeCertificateTrust)` | [VpnClientBuilder.cs:54-67](VpnClientBuilder.cs#L54-L67), [Ikev2Driver.cs:10](../TqkLibrary.VpnClient.Drivers.Ikev2/Ikev2Driver.cs#L10) | (suy luận) — driver "RFC 7296 PSK over NAT-T, CP virtual IP, ESP tunnel mode — no PPP"; logic ở Ipsec `Ike/V2` + `Esp` |
| RFC 4303 (ESP) | `L2tpIpsecDriver` + `Ikev2Driver` (data plane) | [L2tpIpsecDriver.cs:9](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L9), [L2tpIpsecDriver.cs:46](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L46) | (suy luận) — `SecurityKinds = Esp`; hiện thực ở Ipsec `Esp` |
| RFC 3948 (UDP encapsulation / NAT-T) | `L2tpIpsecDriver` (transport UDP) | [L2tpIpsecDriver.cs:9](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L9), [L2tpIpsecDriver.cs:45](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L45) | (suy luận) — "NAT-T"; hiện thực ở [`Ipsec/Nat`](../TqkLibrary.VpnClient.Ipsec/Nat) |
| RFC 2661 (L2TPv2) | `L2tpIpsecDriver` | [L2tpIpsecDriver.cs:9](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L9) | (suy luận) — comment driver "L2TP"; hiện thực ở L2tp |
| RFC 1661/1332 (PPP/IPCP) | `SstpDriver` + `L2tpIpsecDriver` (`UsesPpp`, `AddressAssignment.Ipcp`) | [SstpDriver.cs:37-46](../TqkLibrary.VpnClient.Drivers.Sstp/SstpDriver.cs#L37-L46), [L2tpIpsecDriver.cs:40-49](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L40-L49) | (suy luận) — IP cấp qua IPCP; hiện thực ở Ppp. `Ikev2Driver`/`OpenConnectDriver` thì `UsesPpp = false` (bare IP) |
| OpenVPN (community-server protocol) + NCP AEAD | `OpenVpnDriver` qua `UseOpenVpn()` | [VpnClientBuilder.cs:70-75](VpnClientBuilder.cs#L70-L75), [OpenVpnDriver.cs:16](../TqkLibrary.VpnClient.Drivers.OpenVpn/OpenVpnDriver.cs#L16) | (suy luận) — UDP/TCP, tun-mode (L3) / tap-mode (L2), tls-auth/tls-crypt; logic ở OpenVpn |
| WireGuard (Noise_IKpsk2 + ChaCha20-Poly1305) | `WireGuardDriver` qua `UseWireGuard()` | [VpnClientBuilder.cs:78-82](VpnClientBuilder.cs#L78-L82), [WireGuardDriver.cs:10](../TqkLibrary.VpnClient.Drivers.WireGuard/WireGuardDriver.cs#L10) | (suy luận) — UDP-only, static point-to-point, `SecurityKinds = Noise`, `AddressAssignment.OutOfBand`; logic ở WireGuard |
| OpenConnect (Cisco AnyConnect / ocserv CSTP) + RFC 6347 (DTLS 1.2) | `OpenConnectDriver` qua `UseOpenConnect()` | [VpnClientBuilder.cs:89-101](VpnClientBuilder.cs#L89-L101), [OpenConnectDriver.cs:11](../TqkLibrary.VpnClient.Drivers.OpenConnect/OpenConnectDriver.cs#L11) | (suy luận) — HTTPS config-auth → CSTP, bare IP (no PPP), `X-CSTP-DPD`; data plane DTLS 1.2 (V5.c) fallback TLS — DTLS ở [Transport.Dtls](../TqkLibrary.VpnClient.Transport.Dtls) |
| SoftEther SSL-VPN (Ethernet-over-TLS) | `SoftEtherDriver` qua `UseSoftEther()` | [VpnClientBuilder.cs:107-122](VpnClientBuilder.cs#L107-L122), [SoftEtherDriver.cs:14](../TqkLibrary.VpnClient.Drivers.SoftEther/SoftEtherDriver.cs#L14) | (suy luận) — L2 segment, DHCP-leased IP (`AddressAssignment.Dhcp`), SHA-0 password auth; logic ở SoftEther |
| FIPS-197 (AES), NIST SP 800-38D (AES-GCM) | dùng gián tiếp khi mã hóa ESP/TLS/DTLS | — | (suy luận) — primitive ở Crypto; façade không chạm trực tiếp |

> Tóm lại: dùng bảng này như **bản đồ "shortcut façade → chuẩn"**. Để xem ánh xạ chuẩn → file:line chính xác (có comment RFC trong code), đọc README các project: Drivers, Ipsec (gồm NAT-T `Nat/`), L2tp, Ppp, OpenVpn, WireGuard, SoftEther, Transport.Dtls, Crypto.

## API / cách dùng

Điểm vào public:

- `VpnClientBuilder` →
  - `UseSstp()`, `UseSstp(SstpReconnectOptions)`, `UseSstp(RemoteCertificateValidationCallback)`, `UseSstp(SstpReconnectOptions, RemoteCertificateValidationCallback)`
  - `UseL2tpIpsec()`, `UseL2tpIpsec(L2tpIpsecReconnectOptions)`, `UseL2tpIpsec(L2tpIpsecReconnectOptions, L2tpIpsecTimeoutOptions)`
  - `UseIkev2()`, `UseIkev2(Ikev2ReconnectOptions)`, `UseIkev2(IkeCertificateTrust, Ikev2ReconnectOptions?)`
  - `UseOpenVpn(OpenVpnProfile)`, `UseOpenVpn(OpenVpnProfile, X509CertificateCollection?, RemoteCertificateValidationCallback?, OpenVpnReconnectOptions?)`
  - `UseWireGuard(WireGuardConfig)`, `UseWireGuard(WireGuardConfig, WireGuardReconnectOptions)`
  - `UseOpenConnect()`, `UseOpenConnect(OpenConnectReconnectOptions)`, `UseOpenConnect(OpenConnectReconnectOptions, RemoteCertificateValidationCallback?, string groupSelect)`
  - `UseSoftEther(string hubName)`, `UseSoftEther(string, SoftEtherSessionParams)`, `UseSoftEther(string, SoftEtherSessionParams, SoftEtherReconnectOptions)`, `UseSoftEther(string, bool enableIpv6)`
  - `AddDriver(IVpnProtocolDriver)`, `Build()`.
- `VpnClient` → `ConnectAsync(protocol, endpoint, credentials, ct)`, `Protocols`, `GetCapabilities(protocol)`.

Ví dụ tối thiểu:

```csharp
using TqkLibrary.VpnClient;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

// 1) Đăng ký driver rồi build client
var vpn = new VpnClientBuilder()
    .UseSstp()
    .UseL2tpIpsec()       // auto-reconnect bật mặc định
    .Build();

// 2) Mở kết nối theo tên giao thức
var endpoint = new VpnEndpoint("vpn.example.com", 443);
var creds = new VpnCredentials { Username = "user", Password = "pass" };

await using IVpnConnection conn = await vpn.ConnectAsync("sstp", endpoint, creds);

// 3) Mỗi session là một endpoint IP có PacketChannel để cắm IP stack / socket
IVpnSession session = conn.Sessions[0];
var ip = session.Config.AssignedAddress;
```

Tùy biến auto-reconnect cho L2TP/IPsec:

```csharp
var vpn = new VpnClientBuilder()
    .UseL2tpIpsec(new L2tpIpsecReconnectOptions { Enabled = false }) // single-shot
    .Build();
```

## Luồng nội bộ

Façade rất mỏng, gồm hai bước:

1. **Đăng ký (build-time).** Các shortcut `UseSstp()`/`UseL2tpIpsec()`/`UseIkev2()`/`UseOpenVpn()`/`UseWireGuard()`/`UseOpenConnect()`/`UseSoftEther()` tạo driver cụ thể và gọi `AddDriver` để nạp vào `Dictionary<string, IVpnProtocolDriver>` keyed theo `driver.Name` (`"sstp"`, `"l2tp-ipsec"`, `"ikev2"`, `"openvpn"`, `"wireguard"`, `"openconnect"`, `"softether"`) — [VpnClientBuilder.cs:23-122](VpnClientBuilder.cs#L23-L122). `Build()` đóng gói dictionary đó vào `VpnClient` — [VpnClientBuilder.cs:125](VpnClientBuilder.cs#L125).
2. **Kết nối (run-time).** `ConnectAsync` và `GetCapabilities` đều tra driver qua helper chung `ResolveDriver`: nếu không có → `NotSupportedException` kèm danh sách giao thức đã đăng ký (P0.5, đồng nhất 2 đường); nếu có → `ConnectAsync` ủy thác thẳng `driver.ConnectAsync(endpoint, credentials, ct)` và trả `IVpnConnection` — [VpnClient.cs:18-31](VpnClient.cs#L18-L31).

Toàn bộ việc lắp ráp stack (IKE → ESP → L2TP → PPP → IP cho L2TP; TLS/CSTP/DTLS, Noise, Ethernet-over-TLS cho các giao thức khác) diễn ra **bên trong driver**, không nằm ở project này. Bảy driver nằm ở bảy project anh em: [Sstp](../TqkLibrary.VpnClient.Drivers.Sstp), [L2tpIpsec](../TqkLibrary.VpnClient.Drivers.L2tpIpsec), [Ikev2](../TqkLibrary.VpnClient.Drivers.Ikev2) (IKEv2 + ESP tunnel mode, không PPP), [OpenVpn](../TqkLibrary.VpnClient.Drivers.OpenVpn), [WireGuard](../TqkLibrary.VpnClient.Drivers.WireGuard), [OpenConnect](../TqkLibrary.VpnClient.Drivers.OpenConnect) và [SoftEther](../TqkLibrary.VpnClient.Drivers.SoftEther). Ví dụ điều phối L2TP/IPsec: `L2tpIpsecDriver.ConnectAsync` kiểm PSK bắt buộc rồi dựng `L2tpIpsecConnection` và gọi `ConnectAsync` của nó — [L2tpIpsecDriver.cs:52-81](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L52-L81). Chi tiết luồng handshake xem [.docs/10 §6](../../.docs/10-codebase-architecture-and-flow.md).

## Trạng thái & ghi chú

- **Driver đã wire:** `sstp`, `l2tp-ipsec`, `ikev2`, `openvpn`, `wireguard`, `openconnect`, `softether` (qua các shortcut `UseSstp()`/`UseL2tpIpsec()`/`UseIkev2()`/`UseOpenVpn()`/`UseWireGuard()`/`UseOpenConnect()`/`UseSoftEther()`). Driver tùy ý khác có thể nạp qua `AddDriver(IVpnProtocolDriver)`.
- **L2TP/IPsec chạy trên IKEv1** (đã kiểm chứng live trên VPN Gate); IKEv2-native là driver `ikev2` riêng (qua `UseIkev2()`), không dùng chung connection với L2TP.
- **PSK bắt buộc (L2TP + IKEv2):** `L2tpIpsecDriver` **không** nhét PSK mặc định — `VpnCredentials.PreSharedKey` null/rỗng ⇒ ném `ArgumentException` (default credential đặc thù VPN Gate không thuộc lib chung) — [L2tpIpsecDriver.cs:54-58](../TqkLibrary.VpnClient.Drivers.L2tpIpsec/L2tpIpsecDriver.cs#L54-L58); `Ikev2Driver` cũng yêu cầu PSK tương tự — [Ikev2Driver.cs:61-64](../TqkLibrary.VpnClient.Drivers.Ikev2/Ikev2Driver.cs#L61-L64). Group PSK `"vpn"` của VPN Gate nằm ở tầng demo ([VpnTarget ctor `?psk=` default :21](../../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L21)).
- **Multi-host:** `OpenSessionAsync` được khai báo ở `IVpnConnection`. SSTP/L2TP/IKEv2/WireGuard/OpenConnect đặt `MultiHostModel.None` → một session/kết nối; `OpenVpnDriver` (tap-mode) và `SoftEtherDriver` có thể bật chế độ **multi-host L2** (`MultiHostModel.L2BroadcastDomain`) → mỗi station một session.
- **netstandard2.0 vs net8.0:** không khác biệt API ở tầng façade; khác biệt chỉ phát sinh tận tầng Crypto/Transport (BouncyCastle cho AES-GCM trên netstandard2.0, DTLS qua BouncyCastle ở [Transport.Dtls](../TqkLibrary.VpnClient.Transport.Dtls)). `record`/`init` build xanh cả hai TFM nhờ polyfill `TqkLibrary.CompilerServices`.
- **Không ghi vào OS:** façade/driver **không chạm bảng route hệ điều hành**; tất cả là userspace — app tự lái lưu lượng qua `PacketChannel`/sockets trong tunnel.
