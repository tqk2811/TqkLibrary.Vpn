# Vpn2ProxyDemo

Demo: kết nối VPN Gate (**MS-SSTP** và **L2TP/IPsec**) rồi dựng một proxy local chạy trên tunnel, **giữ proxy sống tới khi nhấn Enter** để test VPN duy trì kết nối (keepalive/auto-reconnect) trong khi client trỏ vào proxy.

Luồng: **vpn → IProxySource → ProxyServer → (giữ sống tới khi nhấn Enter)**

```
SstpConnection / L2tpIpsecConnection      (kết nối VPN, nhận IP ảo + DNS + PacketChannel)
        -> new TcpIpStack(channel, ip)    (userspace TCP/IP trong tunnel)
        -> UdpDnsProbe.ResolveAsync(...)   (DNS-over-UDP qua tunnel: VPN có hỗ trợ UDP? + IP của --resolve)
        -> new VpnProxySource(stack)       (IProxySource — adapter inline trong demo này)
        -> new ProxyServer(<proxy-host>:<proxy-port>, source).StartListen()   (HTTP/SOCKS proxy local)
        -> sanity-check 1 lần: HttpClient { Proxy = http://<host>:<port> }.GetStringAsync(checkip)
        -> GIỮ proxy + tunnel sống tới khi nhấn Enter (Ctrl+C cũng dừng)
        => trỏ browser/curl tới proxy: mọi traffic đi qua IP công cộng của VPN server
```

> "SSL-VPN (comfortable)" mà VPN Gate liệt kê là **giao thức riêng của phần mềm SoftEther VPN**, thư viện này chưa hiện thực — nên demo dùng 2 driver đã chạy live: **MS-SSTP** và **L2TP/IPsec**.

## Cấu trúc (mẫu `ICommandModule` — như `TqkLibrary.WinDivert.Demo`)

```
Vpn2ProxyDemo/
├── Program.cs                        một command duy nhất: new CommandModule().Command.Parse(args).InvokeAsync()
├── Properties/launchSettings.json    profile chạy nhanh từng case (--vpn sstp://... / --vpn l2tp://... / help)
├── VpnProxySource.cs                 IProxySource (partial) bọc TcpIpStack; IsSupportUdp=true, Bind/Ipv6=false
├── VpnProxySource.VpnConnectSource.cs        IConnectSource (nested): mở VpnTcpClient qua tunnel, trả Stream cho ProxyServer
├── VpnProxySource.VpnUdpAssociateSource.cs   IUdpAssociateSource (nested): egress UDP đa đích qua UdpConnection (SOCKS5 UDP-ASSOCIATE)
├── UdpDnsProbe.cs                    build/parse gói DNS (RFC 1035) trên VpnUdpClient: probe UDP + phân giải domain qua tunnel
├── UdpDnsProbeResult.cs              kết quả probe: UdpSupported + danh sách IPv4 + số lần thử/thời gian/lỗi
├── VpnTunnel.cs                      bọc TcpIpStack + AssignedDns + vòng đời (IAsyncDisposable); hàm static ConnectSstpAsync(host,port)/ConnectL2tpAsync(host) (dựng driver -> VpnTunnel)
└── CommandModules/
    ├── Interfaces/ICommandModule.cs          hợp đồng: Command Command { get; }
    ├── Enums/VpnProtocol.cs                  enum giao thức: Sstp / L2tp (map từ scheme của --vpn)
    ├── Models/VpnTarget.cs                   parse URI --vpn (scheme://user:pass@host[:port]) -> Protocol/Host/Port/User/Pass (System.Uri); TryParse + thông báo lỗi
    └── CommandModule.cs                      command duy nhất (RootCommand, sealed): --vpn + --check-url/--proxy-host/--proxy-port/--dns-server/--resolve + header/IP/bắt lỗi + probe UDP-DNS + TcpIpStack -> VpnProxySource -> ProxyServer (giữ tới khi nhấn Enter); ConnectAsync dispatch theo VpnTarget.Protocol -> hàm static của VpnTunnel
```

Phân tầng để **mở rộng nhiều dạng VPN**:

- `CommandModule` (command duy nhất): giữ phần dùng chung **`TcpIpStack → VpnProxySource → ProxyServer`** + sanity-check IP 1 lần qua proxy + **giữ proxy sống tới khi nhấn Enter** + bắt lỗi; toàn bộ thông tin VPN gói trong **một option URI `--vpn`** (`scheme://user:pass@host[:port]`), parse bằng `VpnTarget.TryParse`; còn lại là option proxy/DNS.
- Phần connect riêng từng giao thức là **hàm static của `VpnTunnel`** (`ConnectSstpAsync` / `ConnectL2tpAsync`) — mỗi hàm dựng driver tương ứng và trả **`VpnTunnel`** (bọc `TcpIpStack` + vòng đời, sống tới hết `await using`). `CommandModule.ConnectAsync` chỉ `switch` theo `VpnTarget.Protocol`.
- **Thêm dạng VPN mới:** thêm một hàm static `ConnectXxxAsync` trong `VpnTunnel` + một giá trị `VpnProtocol` (scheme mới) + một nhánh trong `switch`. Credential khác (cert/config/key…) thì mở rộng cú pháp URI / parse trong `VpnTarget`.

## Chạy

Args xử lý bằng **System.CommandLine 2.0.7** (một command + `--option`, có `--help`):

```powershell
dotnet run --project demo/Vpn2ProxyDemo                                  # mặc định sstp://vpn:vpn@public-vpn-226.opengw.net (proxy ở 127.0.0.1:cổng-tự-cấp)
dotnet run --project demo/Vpn2ProxyDemo -- --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net          # L2TP/IPsec
dotnet run --project demo/Vpn2ProxyDemo -- --vpn sstp://vpn:vpn@public-vpn-XXX.opengw.net          # đổi server
dotnet run --project demo/Vpn2ProxyDemo -- --vpn l2tp://vpn:vpn@public-vpn-226.opengw.net --proxy-host 0.0.0.0 --proxy-port 18080  # proxy nghe LAN, cổng cố định
dotnet run --project demo/Vpn2ProxyDemo -- --help                       # liệt kê toàn bộ option
```

Proxy được **giữ chạy tới khi nhấn Enter** (hoặc Ctrl+C). Trong lúc đó trỏ browser/curl vào proxy để gửi traffic và quan sát VPN duy trì kết nối:

```powershell
curl -x http://127.0.0.1:18080 https://checkip.amazonaws.com/
```

Hoặc dùng **launch profile** ([Properties/launchSettings.json](Properties/launchSettings.json)) — chọn nhanh trong VS/Rider hoặc CLI:

```powershell
dotnet run --project demo/Vpn2ProxyDemo --launch-profile sstp
dotnet run --project demo/Vpn2ProxyDemo --launch-profile l2tp
```

Profile có sẵn: `sstp`, `l2tp`, `sstp (as proxy)`, `l2tp (as proxy)`, `sstp resolve example.com (UDP DNS)`, `l2tp resolve github.com (UDP DNS via 8.8.8.8)`, `help`.

Một command duy nhất, toàn bộ thông tin VPN gói trong `--vpn` (URI). Option:

| Option | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `--vpn` | `sstp://vpn:vpn@public-vpn-226.opengw.net` | target VPN dạng URI `scheme://user:pass@host[:port]`. `scheme` = `sstp` (MS-SSTP/TLS, default port 443) hoặc `l2tp` (L2TP/IPsec IKEv1 PSK "vpn", NAT-T 500/4500 — bỏ qua port). Thiếu `user:pass` ⇒ mặc định `vpn:vpn` |
| `--check-url` | `https://checkip.amazonaws.com/` | URL sanity-check IP (gọi 1 lần qua proxy khi vừa lên) |
| `--proxy-host` | `127.0.0.1` | IP cho proxy local nghe (`0.0.0.0` = mọi interface để máy khác trong LAN dùng) |
| `--proxy-port` | `0` | cổng proxy local (`0` = tự cấp cổng trống; chỉ định cố định để client trỏ vào ổn định) |
| `--dns-server` | *(rỗng)* | DNS server (IPv4) cho probe UDP qua tunnel; rỗng = dùng DNS do VPN cấp, fallback `8.8.8.8` |
| `--resolve` | `google.com` | tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP) |

## Lưu ý

- **Cần mạng + server còn sống.** Host VPN Gate thay đổi liên tục; nếu `public-vpn-226` đã tắt, lấy host khác từ https://www.vpngate.net/ và đặt vào phần host của `--vpn` (vd `sstp://vpn:vpn@public-vpn-XXX.opengw.net`). Server phải bật đúng giao thức bạn chọn (cột MS-SSTP / L2TP trên trang VPN Gate).
- **Không cần quyền admin** — toàn bộ stack là userspace (không TUN/TAP, không routing table).
- IP `[direct]` (không VPN) in ra đầu tiên để so sánh với IP `[sstp]`/`[l2tp]` đi qua tunnel.
- **Kiểm tra UDP + DNS qua tunnel:** ngay sau khi tunnel lên, demo gửi một truy vấn DNS (bản ghi A) qua **UDP xuyên tunnel** (`UdpDnsProbe` → `VpnUdpClient`, không dùng host DNS) tới `--dns-server` (mặc định: DNS do VPN cấp, fallback `8.8.8.8`). Nhận được phản hồi ⇒ in `VPN HỖ TRỢ UDP` + IPv4 của `--resolve`; timeout sau 3 lần thử ⇒ VPN có thể không định tuyến UDP (hoặc DNS server không reachable — thử `--dns-server` khác). Đây là kênh UDP đi thẳng IP stack.
- **SOCKS5 UDP-ASSOCIATE:** proxy hỗ trợ UDP cho client SOCKS5 (`IsSupportUdp=true`). Client gửi datagram qua proxy, `VpnUdpAssociateSource` relay ra ngoài bằng UDP của tunnel rồi trả về (vd `curl --socks5 127.0.0.1:port --resolve ... ` hoặc một DNS client trỏ qua SOCKS5 UDP). Chỉ IPv4; **BIND không hỗ trợ** (stack active-open-only + địa chỉ tunnel private không routable từ internet).
- **Giữ kết nối:** sau khi proxy lên, demo dừng tại bước `ProxyServer` và chờ Enter — tunnel vẫn chạy keepalive + auto-reconnect (xem driver), nên đây là chỗ test "duy trì kết nối": cứ gửi traffic qua proxy liên tục/định kỳ rồi quan sát log reconnect. Sanity-check checkip lúc đầu lỗi cũng **không** dừng proxy.
- `--proxy-host 0.0.0.0` mở proxy cho cả máy khác trong LAN — chỉ dùng trên mạng tin cậy (proxy không có auth).
- Demo tham chiếu project tới [`src/TqkLibrary.Vpn.Drivers`](../../src/TqkLibrary.Vpn.Drivers) (driver façades) và [`src/TqkLibrary.Vpn.Sockets`](../../src/TqkLibrary.Vpn.Sockets) (`VpnTcpClient`/`VpnUdpClient`/`TcpIpStack`), cùng NuGet `TqkLibrary.Proxy` 1.0.35.
