# 12 — Demo `Vpn2ProxyDemo` (as-built)

> Tài liệu **bám sát code thực tế** cho demo tích hợp proxy (tách riêng khỏi [`10`](10-codebase-architecture-and-flow.md) §9
> để file 10 gọn). Hướng dẫn chạy chi tiết + bảng option đầy đủ ở [`demo/Vpn2ProxyDemo/README-vi.md`](../demo/Vpn2ProxyDemo/README-vi.md);
> file này tập trung kiến trúc/luồng + link `file:line`.

## 1. Mục đích & vị trí

Demo console chứng minh: kết nối VPN Gate (**MS-SSTP** hoặc **L2TP/IPsec**) → biến tunnel thành `IProxySource` của
**`TqkLibrary.Proxy` 1.0.35** → dựng HTTP/SOCKS proxy local định tuyến mọi kết nối **trong** tunnel, rồi **giữ proxy +
tunnel sống tới khi nhấn Enter** (Ctrl+C cũng dừng) để test VPN duy trì kết nối (keepalive/auto-reconnect) trong lúc
client trỏ traffic vào proxy.

Đây là **project demo** ([`demo/Vpn2ProxyDemo`](../demo/Vpn2ProxyDemo)), **không** phải project `src/`. Adapter
`IProxySource`/`IConnectSource` viết **inline trong demo** (chưa tách thành `TqkLibrary.Vpn.Proxy` — xem roadmap
[`11`](11-todo-roadmap.md) mục "Adapter proxy"). Tham chiếu project: `Drivers.L2tpIpsec` + `Drivers.Sstp` + `Sockets`;
NuGet `TqkLibrary.Proxy` 1.0.35.

## 2. Luồng

```
SstpConnection / L2tpIpsecConnection      (kết nối VPN, nhận IP ảo + DNS + PacketChannel)
  -> new TcpIpStack(channel, ip)          (userspace TCP/IP trong tunnel)
  -> UdpDnsProbe.ResolveAsync(stack, dns, domain)  (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của domain)
  -> new VpnProxySource(stack)            (IProxySource — adapter inline trong demo)
  -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()   (HTTP/SOCKS proxy local)
  -> sanity-check 1 lần: HttpClient { Proxy } -> checkip            (lỗi KHÔNG dừng)
  -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
  => client (browser/curl) qua proxy: mọi traffic ra bằng IP công cộng của VPN server
```

Trước khi dựng proxy, command gọi [`ProbeUdpDnsAsync` @ :173](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L173):
gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** bằng [`UdpDnsProbe.ResolveAsync` @ :29](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L29)
(`VpnUdpClient` → `TcpIpStack.BindUdp`). Nhận được phản hồi ⇒ **VPN có định tuyến UDP**, đồng thời in IPv4 phân giải
được. Đây là kênh data plane **độc lập** với proxy TCP (riêng với SOCKS5 UDP-ASSOCIATE — proxy đã `IsSupportUdp=true`).

Mỗi kết nối TCP qua proxy: `ProxyServer` gọi [`VpnProxySource.GetConnectSourceAsync` @ :36](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L36)
→ [`VpnConnectSource.ConnectAsync` @ :33](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L33) resolve host ra IPv4 (host DNS) rồi
`VpnTcpClient.ConnectAsync` dial trong tunnel → [`GetStreamAsync` @ :59](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L59) trả
stream duplex cho proxy bơm traffic. **SOCKS5 UDP-ASSOCIATE** dùng [`VpnUdpAssociateSource` @ :20](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L20)
(egress UDP qua `UdpConnection`). **BIND** vẫn ném `NotSupportedException` — stack active-open-only + địa chỉ tunnel private
không routable từ internet ([VpnProxySource.cs:40-42](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L40-L42)). Chỉ IPv4.

## 3. Thành phần

| File | Vai trò |
|---|---|
| [Program.cs:10](../demo/Vpn2ProxyDemo/Program.cs#L10) | Một command duy nhất: `new CommandModule().Command.Parse(args).InvokeAsync()` (System.CommandLine 2.0.7) |
| [VpnProxySource.cs:16](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L16) | `IProxySource` (partial) bọc `TcpIpStack`; `IsSupportUdp=true`, `Ipv6/Bind=false`; phát `IConnectSource`/`IUdpAssociateSource` |
| [VpnProxySource.VpnConnectSource.cs:17](../demo/Vpn2ProxyDemo/VpnProxySource.VpnConnectSource.cs#L17) | `IConnectSource` (nested): mở `VpnTcpClient` qua tunnel, trả `Stream` (resolve IPv4 bằng host DNS) |
| [VpnProxySource.VpnUdpAssociateSource.cs:20](../demo/Vpn2ProxyDemo/VpnProxySource.VpnUdpAssociateSource.cs#L20) | `IUdpAssociateSource` (nested): egress UDP qua `UdpConnection` (`SendTo`/`ReceiveAsync` đa đích), `UnbindUdp` khi `Dispose` |
| [UdpDnsProbe.cs:18](../demo/Vpn2ProxyDemo/UdpDnsProbe.cs#L18) | Build/parse gói DNS (RFC 1035) trên `VpnUdpClient` → gửi truy vấn A qua UDP xuyên tunnel (kiểm tra UDP + phân giải domain), retry + timeout |
| [UdpDnsProbeResult.cs:11](../demo/Vpn2ProxyDemo/UdpDnsProbeResult.cs#L11) | Kết quả probe: `UdpSupported` + danh sách IPv4 + số lần thử/thời gian/lỗi |
| [VpnTunnel.cs:21](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L21) | Bọc `TcpIpStack` + `AssignedDns` + vòng đời tunnel (`IAsyncDisposable`); **hàm static connect** [`ConnectSstpAsync` @ :41](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L41) (MS-SSTP/TLS, nhận `host`+`port`) + [`ConnectL2tpAsync` @ :65](../demo/Vpn2ProxyDemo/VpnTunnel.cs#L65) (L2TP/IPsec IKEv1 PSK "vpn", NAT-T — không port) — mỗi hàm dựng driver → `SstpConnection`/`L2tpIpsecConnection` → `TcpIpStack` → `VpnTunnel` |
| [CommandModules/Interfaces/ICommandModule.cs:6](../demo/Vpn2ProxyDemo/CommandModules/Interfaces/ICommandModule.cs#L6) | Hợp đồng command: `Command Command { get; }` |
| [CommandModules/Enums/VpnProtocol.cs:4](../demo/Vpn2ProxyDemo/CommandModules/Enums/VpnProtocol.cs#L4) | Enum giao thức (`Sstp` / `L2tp`) — map từ scheme của URI `--vpn` |
| [CommandModules/Models/VpnTarget.cs:13](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L13) | Tham số kết nối parse từ `--vpn` (`scheme://user:pass@host[:port]`); [`TryParse` @ :37](../demo/Vpn2ProxyDemo/CommandModules/Models/VpnTarget.cs#L37) dùng `System.Uri` → `Protocol/Host/Port/User/Pass` (thiếu user:pass ⇒ `vpn:vpn`; SSTP thiếu port ⇒ 443) + thông báo lỗi |
| [CommandModules/CommandModule.cs:26](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L26) | Command duy nhất (`RootCommand`, sealed): option `--vpn` (URI) + `--check-url/--proxy-host/--proxy-port/--dns-server/--resolve`, header/IP/bắt lỗi; probe UDP-DNS + phần dùng chung `TcpIpStack → VpnProxySource → ProxyServer` + **giữ tới khi nhấn Enter**; [`ConnectAsync` @ :144](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L144) dispatch theo `VpnTarget.Protocol` về hàm static của `VpnTunnel` |

Luồng điều phối chung nằm ở command: [`InvokeAsync` @ :83](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L83)
(parse `--vpn` bằng `VpnTarget.TryParse` + validate proxy-host/port, in IP direct, [`ConnectAsync` @ :144](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L144) dispatch theo giao thức) →
[`ProbeUdpDnsAsync` @ :157](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L157) (test UDP + DNS qua tunnel) →
[`RunProxyUntilEnterAsync` @ :199](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L199) (bind `ProxyServer`,
sanity-check, giữ sống) → [`WaitForEnterAsync` @ :244](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L244)
(chờ Enter **hoặc** `ct` hủy bằng Ctrl+C; `Console.ReadLine()` chạy trên thread pool nên không chặn process exit).

## 4. Tham số CLI (một command, target VPN gói trong option `--vpn`)

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN dạng URI `scheme://user:pass@host[:port]`. `scheme` = `sstp` (MS-SSTP/TLS, default port 443) hoặc `l2tp` (L2TP/IPsec IKEv1 PSK "vpn", NAT-T 500/4500 — bỏ qua port). Thiếu `user:pass` ⇒ mặc định `vpn:vpn` |
| `--check-url` | `https://checkip.amazonaws.com/` | URL sanity-check IP (gọi 1 lần qua proxy khi vừa lên) |
| `--proxy-host` | `127.0.0.1` | IP cho proxy local nghe (`0.0.0.0` = mọi interface cho máy khác trong LAN) |
| `--proxy-port` | `0` | cổng proxy local (`0` = tự cấp; cố định để client trỏ vào ổn định) |
| `--dns-server` | *(rỗng)* | DNS server (IPv4) cho probe UDP; rỗng = dùng DNS do VPN cấp, fallback `8.8.8.8` |
| `--resolve` | `google.com` | tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP) |

Bind `0.0.0.0` thì sanity-check vẫn nối qua `127.0.0.1`; bind IP cụ thể thì nối thẳng IP đó
([CommandModule.cs:206-207](../demo/Vpn2ProxyDemo/CommandModules/CommandModule.cs#L206-L207)).

## 5. Trạng thái & chưa làm

- ✅ HTTP/HTTPS CONNECT + SOCKS4/5 CONNECT qua tunnel (chỉ IPv4, active-open) cho **cả** MS-SSTP và L2TP/IPsec.
- ✅ **SOCKS5 UDP-ASSOCIATE qua proxy** (`VpnUdpAssociateSource` → `UdpConnection`): client gửi UDP qua proxy, server
  relay datagram ra ngoài bằng userspace UDP của stack (đa đích, `SendTo`/`ReceiveAsync`); socket được `UnbindUdp` khi
  association đóng. IPv4-only (đích IPv6 bị từ chối).
- ✅ Giữ proxy + tunnel sống tới khi nhấn Enter (test duy trì kết nối: keepalive/auto-reconnect của driver chạy nền).
- ✅ **Probe UDP + DNS-over-UDP qua tunnel** (`UdpDnsProbe` → `VpnUdpClient`): vừa kiểm tra VPN có định tuyến UDP
  vừa phân giải `--resolve` ra IPv4 (đích DNS = `--dns-server` / DNS VPN cấp / `8.8.8.8`). Đây là data plane UDP
  thật, độc lập với proxy TCP.
- ⏳ **Chưa:** BIND (stack active-open-only + địa chỉ tunnel private không routable từ internet ⇒ peer ngoài không
  dial vào được), proxy resolve host vẫn bằng host DNS, IPv6. Tách adapter thành project `TqkLibrary.Vpn.Proxy` nếu
  cần tái dùng — xem [`11`](11-todo-roadmap.md).
