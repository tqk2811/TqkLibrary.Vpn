using System.CommandLine;
using System.Net;
using System.Net.Http;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp;
using Vpn2ProxyDemo.CommandModules.Enums;
using Vpn2ProxyDemo.CommandModules.Interfaces;
using Vpn2ProxyDemo.CommandModules.Models;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Command duy nhất của demo VPN. Toàn bộ thông tin kết nối gói trong một option URI <c>--vpn</c>
    /// (<c>scheme://user:pass@host[:port]</c>) — <c>scheme</c> chọn giao thức (SSTP / L2TP), <c>user:pass</c> là
    /// credential, <c>host[:port]</c> là gateway. Giữ option chung (<c>--check-url</c> +
    /// <c>--proxy-host</c>/<c>--proxy-port</c> + <c>--dns-server</c>/<c>--resolve</c>), in header + IP trực tiếp, bắt lỗi,
    /// rồi chạy phần dùng chung <c>TcpIpStack -> VpnProxySource -> ProxyServer</c> và **giữ proxy sống tới khi người dùng
    /// nhấn Enter** (test duy trì kết nối VPN qua keepalive/auto-reconnect).
    /// <para>
    /// Phần connect riêng từng giao thức nằm ở hàm static của <see cref="VpnTunnel"/>
    /// (<see cref="VpnTunnel.ConnectSstpAsync"/> / <see cref="VpnTunnel.ConnectL2tpAsync"/>); <see cref="ConnectAsync"/>
    /// chỉ dispatch theo <see cref="VpnProtocol"/> đã parse. Thêm một giao thức mới = thêm một hàm static + một nhánh switch.
    /// </para>
    /// </summary>
    internal sealed class CommandModule : ICommandModule
    {
        Option<string> VpnOption { get; }
        Option<string> CheckUrlOption { get; }
        Option<string> ProxyHostOption { get; }
        Option<int> ProxyPortOption { get; }
        Option<string> DnsServerOption { get; }
        Option<string> ResolveOption { get; }

        readonly RootCommand _command;
        public Command Command => _command;

        public CommandModule()
        {
            _command = new RootCommand("Demo: VPN (MS-SSTP / L2TP-IPsec) -> IProxySource -> ProxyServer -> HttpClient -> checkip.");

            VpnOption = new Option<string>("--vpn")
            {
                Description = "VPN target dạng URI scheme://user:pass@host[:port]. scheme = sstp (MS-SSTP/TLS, default port 443) "
                    + "hoặc l2tp (L2TP/IPsec IKEv1 PSK \"vpn\", NAT-T 500/4500 — bỏ qua port). Thiếu user:pass ⇒ mặc định vpn:vpn.",
                DefaultValueFactory = _ => "sstp://vpn:vpn@public-vpn-226.opengw.net",
            };
            CheckUrlOption = new Option<string>("--check-url")
            {
                Description = "URL sanity-check IP công cộng (gọi 1 lần qua proxy khi vừa lên, không chặn việc giữ proxy).",
                DefaultValueFactory = _ => "https://checkip.amazonaws.com/",
            };
            ProxyHostOption = new Option<string>("--proxy-host")
            {
                Description = "Địa chỉ IP cho proxy local lắng nghe (0.0.0.0 = mọi interface để máy khác trong LAN dùng).",
                DefaultValueFactory = _ => "127.0.0.1",
            };
            ProxyPortOption = new Option<int>("--proxy-port")
            {
                Description = "Cổng proxy local (0 = tự cấp một cổng trống; chỉ định cố định để client trỏ vào ổn định).",
                DefaultValueFactory = _ => 0,
            };
            DnsServerOption = new Option<string>("--dns-server")
            {
                Description = "DNS server (IPv4) cho phép thử UDP qua tunnel. Bỏ trống = dùng DNS do VPN cấp, fallback 8.8.8.8.",
                DefaultValueFactory = _ => "",
            };
            ResolveOption = new Option<string>("--resolve")
            {
                Description = "Tên miền phân giải bằng DNS-over-UDP qua tunnel (đồng thời kiểm tra VPN có hỗ trợ UDP).",
                DefaultValueFactory = _ => "google.com",
            };
            _command.Options.Add(VpnOption);
            _command.Options.Add(CheckUrlOption);
            _command.Options.Add(ProxyHostOption);
            _command.Options.Add(ProxyPortOption);
            _command.Options.Add(DnsServerOption);
            _command.Options.Add(ResolveOption);

            _command.SetAction(InvokeAsync);
        }

        async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
        {
            string vpnUri = parseResult.GetValue(VpnOption)!;
            string checkUrl = parseResult.GetValue(CheckUrlOption)!;
            string proxyHost = parseResult.GetValue(ProxyHostOption)!;
            int proxyPort = parseResult.GetValue(ProxyPortOption);
            string dnsServer = parseResult.GetValue(DnsServerOption)!;
            string resolveDomain = parseResult.GetValue(ResolveOption)!;

            if (!VpnTarget.TryParse(vpnUri, out VpnTarget? target, out string? vpnError))
            {
                Console.WriteLine($"  !! {vpnError}");
                return 1;
            }
            if (!IPAddress.TryParse(proxyHost, out IPAddress? bindAddress))
            {
                Console.WriteLine($"  !! --proxy-host '{proxyHost}' không phải IP hợp lệ (vd 127.0.0.1 hoặc 0.0.0.0).");
                return 1;
            }
            if (proxyPort < 0 || proxyPort > 65535)
            {
                Console.WriteLine($"  !! --proxy-port {proxyPort} ngoài khoảng 0..65535.");
                return 1;
            }

            // Tag protocol cho log/header ("sstp"/"l2tp") — trước đây là tên subcommand.
            string tag = target!.Protocol.ToString().ToLowerInvariant();

            PrintHeader(tag, checkUrl);

            // IP thật (không qua VPN) để so sánh.
            await PrintDirectIpAsync(checkUrl);
            Console.WriteLine();

            try
            {
                // Connect VPN theo giao thức đã chọn và trả về tunnel (giữ vòng đời kết nối).
                await using VpnTunnel tunnel = await ConnectAsync(target, ct);

                // Kiểm tra VPN có định tuyến UDP không + phân giải DNS-over-UDP qua tunnel.
                await ProbeUdpDnsAsync(tag, tunnel.Stack, tunnel.AssignedDns, dnsServer, resolveDomain, ct);

                // Phần dùng chung: stack -> IProxySource -> ProxyServer; giữ proxy sống tới khi nhấn Enter.
                IProxySource source = new VpnProxySource(tunnel.Stack);
                await RunProxyUntilEnterAsync(tag, source, new IPEndPoint(bindAddress, proxyPort), checkUrl, ct);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("  (đã hủy)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  !! {ex.GetType().Name}: {ex.Message}");
                Console.WriteLine();
            }

            Console.WriteLine("Done.");
            return 0;
        }

        /// <summary>Dispatch connect theo giao thức đã parse về hàm static tương ứng của <see cref="VpnTunnel"/>.</summary>
        static Task<VpnTunnel> ConnectAsync(VpnTarget target, CancellationToken ct)
            => target.Protocol switch
            {
                VpnProtocol.Sstp => VpnTunnel.ConnectSstpAsync(target.Host, target.Port, target.User, target.Pass, ct),
                VpnProtocol.L2tp => VpnTunnel.ConnectL2tpAsync(target.Host, target.User, target.Pass, ct),
                _ => throw new ArgumentOutOfRangeException(nameof(target), target.Protocol, "Giao thức VPN không hỗ trợ."),
            };

        /// <summary>
        /// Gửi một truy vấn DNS (bản ghi A) cho <paramref name="domain"/> qua UDP xuyên tunnel để kiểm tra VPN có
        /// định tuyến UDP hay không, và in IPv4 phân giải được. Đích DNS: <paramref name="dnsServerOpt"/> nếu là IP
        /// hợp lệ; ngược lại dùng DNS do VPN cấp (<paramref name="assignedDns"/>), fallback 8.8.8.8. Lỗi chỉ in cảnh báo.
        /// </summary>
        async Task ProbeUdpDnsAsync(string tag, TcpIpStack stack, IPAddress? assignedDns, string dnsServerOpt, string domain, CancellationToken ct)
        {
            IPAddress dnsServer = !string.IsNullOrWhiteSpace(dnsServerOpt) && IPAddress.TryParse(dnsServerOpt, out IPAddress? parsed)
                ? parsed
                : assignedDns ?? IPAddress.Parse("8.8.8.8");

            Console.WriteLine($"[{tag}] UDP test: gửi truy vấn DNS (A) cho '{domain}' tới {dnsServer}:53 qua tunnel...");
            try
            {
                UdpDnsProbeResult result = await UdpDnsProbe.ResolveAsync(
                    stack, dnsServer, domain, attempts: 3, perAttemptTimeout: TimeSpan.FromSeconds(3), ct);

                if (result.UdpSupported)
                {
                    Console.WriteLine($"[{tag}] => VPN HỖ TRỢ UDP (nhận phản hồi ở lần thử {result.Attempts}, {result.Elapsed.TotalMilliseconds:F0} ms).");
                    if (result.Addresses.Count > 0)
                        Console.WriteLine($"[{tag}] => {domain} = {string.Join(", ", result.Addresses)}");
                    else
                        Console.WriteLine($"[{tag}] => (không có bản ghi A: {result.Error})");
                }
                else
                {
                    Console.WriteLine($"[{tag}] => VPN có thể KHÔNG hỗ trợ/định tuyến UDP: {result.Error} (đã chờ {result.Elapsed.TotalMilliseconds:F0} ms).");
                    Console.WriteLine($"[{tag}]    (cũng có thể do DNS server {dnsServer} không reachable — thử --dns-server khác).");
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{tag}] UDP test lỗi (vẫn tiếp tục chạy proxy): {ex.GetType().Name}: {ex.Message}");
            }
            Console.WriteLine();
        }

        /// <summary>
        /// Phần dùng chung: cắm <paramref name="source"/> vào ProxyServer (bind theo <paramref name="bind"/>),
        /// sanity-check IP 1 lần qua proxy, rồi **giữ proxy + tunnel sống tới khi nhấn Enter** (hoặc Ctrl+C) —
        /// để test VPN duy trì kết nối (keepalive/auto-reconnect) trong khi client trỏ vào proxy.
        /// </summary>
        async Task RunProxyUntilEnterAsync(string tag, IProxySource source, IPEndPoint bind, string checkUrl, CancellationToken ct)
        {
            using var proxyServer = new ProxyServer(bind, source);
            proxyServer.StartListen();
            int port = proxyServer.IPEndPoint!.Port;

            // Bind 0.0.0.0 nghe mọi interface → client cục bộ vẫn nối qua 127.0.0.1; ngược lại nối thẳng địa chỉ bind.
            string listenHost = bind.Address.ToString();
            string clientHost = bind.Address.Equals(IPAddress.Any) ? "127.0.0.1" : listenHost;
            string displayUrl = $"http://{listenHost}:{port}";
            string clientUrl = $"http://{clientHost}:{port}";
            Console.WriteLine($"[{tag}] local proxy listening at {displayUrl}");

            // Sanity-check 1 lần qua proxy — lỗi cũng KHÔNG dừng (vẫn giữ proxy để test thủ công).
            await CheckIpThroughProxyAsync(tag, clientUrl, checkUrl);

            Console.WriteLine();
            Console.WriteLine($"[{tag}] Proxy đang chạy — mọi kết nối qua proxy được định tuyến trong VPN tunnel.");
            Console.WriteLine($"[{tag}] Trỏ trình duyệt/curl tới {displayUrl} để test; kết nối DUY TRÌ tới khi bạn nhấn Enter...");
            await WaitForEnterAsync(ct);
            Console.WriteLine($"[{tag}] đang dừng proxy + đóng tunnel...");
        }

        /// <summary>Gọi <paramref name="checkUrl"/> 1 lần qua proxy <paramref name="proxyUrl"/> để xác nhận đường đi; lỗi chỉ in cảnh báo.</summary>
        static async Task CheckIpThroughProxyAsync(string tag, string proxyUrl, string checkUrl)
        {
            try
            {
                using var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy(proxyUrl),
                    UseProxy = true,
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(40) };

                string ip = (await http.GetStringAsync(checkUrl)).Trim();
                Console.WriteLine($"[{tag}] checkip qua VPN proxy => {ip}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{tag}] sanity checkip lỗi (vẫn giữ proxy): {ex.GetType().Name}: {ex.Message}");
            }
        }

        /// <summary>Chờ tới khi người dùng nhấn Enter trên console, hoặc <paramref name="ct"/> bị hủy (Ctrl+C).</summary>
        static async Task WaitForEnterAsync(CancellationToken ct)
        {
            // Console.ReadLine() chạy trên thread pool (background thread) nên không chặn process exit.
            Task enter = Task.Run(() => Console.ReadLine());
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (ct.Register(() => cancelled.TrySetResult(true)))
            {
                await Task.WhenAny(enter, cancelled.Task);
            }
        }

        static void PrintHeader(string protocol, string checkUrl)
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" VPN -> IProxySource -> ProxyServer (giữ tới khi nhấn Enter)");
            Console.WriteLine("============================================================");
            Console.WriteLine($"Protocol : {protocol}");
            Console.WriteLine($"Target   : {checkUrl}");
            Console.WriteLine();
        }

        static async Task PrintDirectIpAsync(string checkUrl)
        {
            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
                string ip = (await http.GetStringAsync(checkUrl)).Trim();
                Console.WriteLine($"[direct] IP công cộng thật (không VPN) => {ip}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[direct] không lấy được IP thật: {ex.Message}");
            }
        }
    }
}
