using Microsoft.Extensions.Logging;
using System.CommandLine;
using System.Net;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Interfaces;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Subcommand <c>proxy-server</c>: cắm tunnel thành <see cref="IProxySource"/> rồi dựng HTTP/SOCKS proxy local định
    /// tuyến mọi kết nối <b>trong</b> tunnel, và <b>giữ proxy + tunnel sống tới khi nhấn Enter</b> (test VPN duy trì kết
    /// nối: keepalive/auto-reconnect).
    /// <para>
    /// Việc làm khi proxy đã listen tách ra <see cref="OnProxyReadyAsync"/> (mặc định: giữ tới khi nhấn Enter) để subclass
    /// override — vd <see cref="HttpRequestProxyServerCommandModule"/> GET một URL qua proxy rồi thoát.
    /// </para>
    /// </summary>
    internal class ProxyServerCommandModule : CommandModuleBase
    {
        Option<string> ProxyHostOption { get; }
        Option<int> ProxyPortOption { get; }

        public ProxyServerCommandModule()
            : this("proxy-server", "Dựng proxy local định tuyến trong tunnel, giữ tới khi nhấn Enter.")
        {
        }

        protected ProxyServerCommandModule(string name, string description) : base(name, description)
        {
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
            Command.Options.Add(ProxyHostOption);
            Command.Options.Add(ProxyPortOption);
        }

        protected override string? ValidateOptions(ParseResult parseResult)
        {
            string proxyHost = parseResult.GetValue(ProxyHostOption)!;
            int proxyPort = parseResult.GetValue(ProxyPortOption);
            if (!IPAddress.TryParse(proxyHost, out _))
                return $"--proxy-host '{proxyHost}' không phải IP hợp lệ (vd 127.0.0.1 hoặc 0.0.0.0).";
            if (proxyPort < 0 || proxyPort > 65535)
                return $"--proxy-port {proxyPort} ngoài khoảng 0..65535.";
            return null;
        }

        protected override async Task RunAsync(string tag, VpnTunnel tunnel, ParseResult parseResult, CancellationToken ct)
        {
            // ValidateOptions đã đảm bảo proxy-host/port hợp lệ trước khi connect.
            IPAddress bindAddress = IPAddress.Parse(parseResult.GetValue(ProxyHostOption)!);
            int proxyPort = parseResult.GetValue(ProxyPortOption);

            // Logger console: tách bạch để dispose flush sau khi proxy dừng (khai báo trước proxyServer ⇒ dispose sau).
            using ILoggerFactory loggerFactory = CreateLoggerFactory();

            // Phần dùng chung: stack -> IProxySource -> ProxyServer (cùng chia sẻ ILoggerFactory).
            // Bật egress IPv6 khi tunnel cấp IPv6 global (stack đã dual-stack — P1.1); link-local/không-v6 ⇒ IPv4-only.
            IProxySource source = new VpnProxySource(tunnel.Stack, loggerFactory, supportIpv6: tunnel.AssignedAddressV6 is not null);
            using var proxyServer = new ProxyServer(new IPEndPoint(bindAddress, proxyPort), source, loggerFactory);
            proxyServer.StartListen();
            int port = proxyServer.IPEndPoint!.Port;

            // Bind 0.0.0.0 nghe mọi interface → client cục bộ vẫn nối qua 127.0.0.1; ngược lại nối thẳng địa chỉ bind.
            string listenHost = bindAddress.ToString();
            string clientHost = bindAddress.Equals(IPAddress.Any) ? "127.0.0.1" : listenHost;
            string displayUrl = $"http://{listenHost}:{port}";
            string clientUrl = $"http://{clientHost}:{port}";
            Console.WriteLine($"[{tag}] local proxy listening at {displayUrl}");

            await OnProxyReadyAsync(tag, clientUrl, displayUrl, parseResult, ct);

            Console.WriteLine($"[{tag}] đang dừng proxy + đóng tunnel...");
        }

        /// <summary>
        /// Việc làm khi proxy đã listen. Mặc định: <b>giữ proxy + tunnel sống tới khi nhấn Enter</b> (hoặc Ctrl+C).
        /// Subclass override để làm việc khác rồi thoát (vd gửi một HTTP request qua proxy).
        /// <paramref name="clientProxyUrl"/> là URL client nên trỏ vào (đã quy 0.0.0.0 → 127.0.0.1).
        /// </summary>
        protected virtual async Task OnProxyReadyAsync(string tag, string clientProxyUrl, string displayUrl, ParseResult parseResult, CancellationToken ct)
        {
            Console.WriteLine();
            Console.WriteLine($"[{tag}] Proxy đang chạy — mọi kết nối qua proxy được định tuyến trong VPN tunnel.");
            Console.WriteLine($"[{tag}] Trỏ trình duyệt/curl tới {displayUrl} để test; kết nối DUY TRÌ tới khi bạn nhấn Enter...");
            await WaitForEnterAsync(ct);
        }

        /// <summary>Console logger cho ProxyServer + VpnProxySource: mức Information, riêng category <c>Vpn2ProxyDemo</c> ở Debug (hiện log connect/UDP của demo).</summary>
        ILoggerFactory CreateLoggerFactory()
            => LoggerFactory.Create(builder => builder
                .SetMinimumLevel(LogLevel.Information)
                .AddFilter("Vpn2ProxyDemo", LogLevel.Debug)
                .AddSimpleConsole(options =>
                {
                    options.SingleLine = true;
                    options.TimestampFormat = "HH:mm:ss.fff ";
                }));

        /// <summary>Chờ tới khi người dùng nhấn Enter trên console, hoặc <paramref name="ct"/> bị hủy (Ctrl+C).</summary>
        async Task WaitForEnterAsync(CancellationToken ct)
        {
            // Console.ReadLine() chạy trên thread pool (background thread) nên không chặn process exit.
            Task enter = Task.Run(() => Console.ReadLine());
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (ct.Register(() => cancelled.TrySetResult(true)))
            {
                await Task.WhenAny(enter, cancelled.Task);
            }
        }
    }
}
