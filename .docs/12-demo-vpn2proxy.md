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
SstpConnection / L2tpIpsecConnection      (kết nối VPN, nhận IP ảo + PacketChannel)
  -> new TcpIpStack(channel, ip)          (userspace TCP/IP trong tunnel)
  -> new VpnProxySource(stack)            (IProxySource — adapter inline trong demo)
  -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()   (HTTP/SOCKS proxy local)
  -> sanity-check 1 lần: HttpClient { Proxy } -> checkip            (lỗi KHÔNG dừng)
  -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
  => client (browser/curl) qua proxy: mọi traffic ra bằng IP công cộng của VPN server
```

Mỗi kết nối qua proxy: `ProxyServer` gọi [`VpnProxySource.GetConnectSourceAsync` @ :35](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L35)
→ [`VpnConnectSource.ConnectAsync` @ :32](../demo/Vpn2ProxyDemo/VpnConnectSource.cs#L32) resolve host ra IPv4 (host DNS) rồi
`VpnTcpClient.ConnectAsync` dial trong tunnel → [`GetStreamAsync` @ :58](../demo/Vpn2ProxyDemo/VpnConnectSource.cs#L58) trả
stream duplex cho proxy bơm traffic. **Chỉ IPv4 + active-open** ⇒ BIND/UDP-ASSOCIATE ném `NotSupportedException`
([VpnProxySource.cs:39-44](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L39-L44)).

## 3. Thành phần

| File | Vai trò |
|---|---|
| [Program.cs:10](../demo/Vpn2ProxyDemo/Program.cs#L10) | `RootCommand { sstp, l2tp }` → `Parse(args).InvokeAsync()` (System.CommandLine 2.0.7) |
| [VpnProxySource.cs:15](../demo/Vpn2ProxyDemo/VpnProxySource.cs#L15) | `IProxySource` bọc `TcpIpStack` của tunnel; `IsSupportUdp/Ipv6/Bind=false` |
| [VpnConnectSource.cs:16](../demo/Vpn2ProxyDemo/VpnConnectSource.cs#L16) | `IConnectSource`: mở `VpnTcpClient` qua tunnel, trả `Stream` (resolve IPv4 bằng host DNS) |
| [CommandModules/Interfaces/ICommandModule.cs:6](../demo/Vpn2ProxyDemo/CommandModules/Interfaces/ICommandModule.cs#L6) | Hợp đồng subcommand: `Command Command { get; }` |
| [CommandModuleBase.cs:21](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L21) | Base GENERIC: option `--check-url`/`--proxy-host`/`--proxy-port`, header/IP/bắt lỗi; phần dùng chung `TcpIpStack → VpnProxySource → ProxyServer` + **giữ tới khi nhấn Enter**; abstract `ConnectAsync(ParseResult)` |
| [HostCredentialCommandModuleBase.cs:11](../demo/Vpn2ProxyDemo/CommandModules/HostCredentialCommandModuleBase.cs#L11) | Base cho VPN dùng host+user+pass: thêm `--host/--user/--pass` → `ConnectAsync(host,user,pass,ct)` |
| [VpnTunnel.cs:13](../demo/Vpn2ProxyDemo/CommandModules/VpnTunnel.cs#L13) | Bọc `TcpIpStack` + vòng đời tunnel (`IAsyncDisposable`) — kiểu mà `ConnectAsync` trả về |
| [SstpCommandModule.cs:7](../demo/Vpn2ProxyDemo/CommandModules/SstpCommandModule.cs#L7) | `"sstp"`: `ConnectAsync` → `SstpConnection` (MS-SSTP/TLS 443) → `VpnTunnel` |
| [L2tpCommandModule.cs:8](../demo/Vpn2ProxyDemo/CommandModules/L2tpCommandModule.cs#L8) | `"l2tp"`: `ConnectAsync` → `L2tpIpsecConnection` (IKEv1 PSK "vpn", NAT-T) → `VpnTunnel` |

Luồng điều phối chung nằm ở base: [`InvokeAsync` @ :56](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L56)
(parse + validate proxy-host/port, in IP direct, gọi lớp con connect) →
[`RunProxyUntilEnterAsync` @ :110](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L110) (bind `ProxyServer`,
sanity-check, giữ sống) → [`WaitForEnterAsync` @ :155](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L155)
(chờ Enter **hoặc** `ct` hủy bằng Ctrl+C; `Console.ReadLine()` chạy trên thread pool nên không chặn process exit).

## 4. Tham số CLI (mỗi subcommand `sstp`/`l2tp`)

| Option | Mặc định | Ý nghĩa |
|---|---|---|
| `--host` | `public-vpn-226.opengw.net` | host VPN Gate |
| `--user` / `--pass` | `vpn` / `vpn` | tài khoản VPN Gate |
| `--check-url` | `https://checkip.amazonaws.com/` | URL sanity-check IP (gọi 1 lần qua proxy khi vừa lên) |
| `--proxy-host` | `127.0.0.1` | IP cho proxy local nghe (`0.0.0.0` = mọi interface cho máy khác trong LAN) |
| `--proxy-port` | `0` | cổng proxy local (`0` = tự cấp; cố định để client trỏ vào ổn định) |

Bind `0.0.0.0` thì sanity-check vẫn nối qua `127.0.0.1`; bind IP cụ thể thì nối thẳng IP đó
([CommandModuleBase.cs:116-120](../demo/Vpn2ProxyDemo/CommandModules/CommandModuleBase.cs#L116-L120)).

## 5. Trạng thái & chưa làm

- ✅ HTTP/HTTPS CONNECT + SOCKS4/5 CONNECT qua tunnel (chỉ IPv4, active-open) cho **cả** MS-SSTP và L2TP/IPsec.
- ✅ Giữ proxy + tunnel sống tới khi nhấn Enter (test duy trì kết nối: keepalive/auto-reconnect của driver chạy nền).
- ⏳ **Chưa:** BIND, UDP-ASSOCIATE (đã có `VpnUdpClient`, cần SOCKS5 UDP framing), DNS-over-tunnel (đang resolve bằng
  host DNS), IPv6. Tách adapter thành project `TqkLibrary.Vpn.Proxy` nếu cần tái dùng — xem [`11`](11-todo-roadmap.md).
