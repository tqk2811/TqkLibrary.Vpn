using System.CommandLine;
using System.Net;
using System.Net.Http;
using TqkLibrary.Proxy;
using TqkLibrary.Proxy.Interfaces;
using Vpn2ProxyDemo.CommandModules.Interfaces;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Base chung cho mọi command module VPN của demo — **không gắn với protocol hay kiểu credential cụ thể**.
    /// Giữ option chung (<c>--check-url</c> + <c>--proxy-host</c>/<c>--proxy-port</c>), in header + IP trực tiếp,
    /// bắt lỗi, và chạy phần dùng chung <c>TcpIpStack -> VpnProxySource -> ProxyServer</c> rồi **giữ proxy sống
    /// tới khi người dùng nhấn Enter** (test duy trì kết nối VPN qua keepalive/auto-reconnect).
    /// <para>
    /// Lớp con tự quyết: option riêng (thêm vào <see cref="Command"/> trong ctor của nó) và cách connect
    /// (<see cref="ConnectAsync"/> đọc <see cref="ParseResult"/> rồi trả về <see cref="VpnTunnel"/>). Thêm một
    /// dạng VPN mới = thêm một lớp con, không phải sửa base.
    /// </para>
    /// </summary>
    internal abstract class CommandModuleBase : ICommandModule
    {
        protected Option<string> CheckUrlOption { get; }
        protected Option<string> ProxyHostOption { get; }
        protected Option<int> ProxyPortOption { get; }

        readonly Command _command;
        public Command Command => _command;

        protected CommandModuleBase(string name, string description)
        {
            _command = new Command(name, description);

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
            _command.Options.Add(CheckUrlOption);
            _command.Options.Add(ProxyHostOption);
            _command.Options.Add(ProxyPortOption);

            _command.SetAction(InvokeAsync);
        }

        async Task<int> InvokeAsync(ParseResult parseResult, CancellationToken ct)
        {
            string checkUrl = parseResult.GetValue(CheckUrlOption)!;
            string proxyHost = parseResult.GetValue(ProxyHostOption)!;
            int proxyPort = parseResult.GetValue(ProxyPortOption);

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

            PrintHeader(_command.Name, checkUrl);

            // IP thật (không qua VPN) để so sánh.
            await PrintDirectIpAsync(checkUrl);
            Console.WriteLine();

            try
            {
                // Lớp con connect VPN và trả về tunnel (giữ vòng đời kết nối).
                await using VpnTunnel tunnel = await ConnectAsync(parseResult, ct);

                // Phần dùng chung: stack -> IProxySource -> ProxyServer; giữ proxy sống tới khi nhấn Enter.
                IProxySource source = new VpnProxySource(tunnel.Stack);
                await RunProxyUntilEnterAsync(_command.Name, source, new IPEndPoint(bindAddress, proxyPort), checkUrl, ct);
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

        /// <summary>Đọc option riêng của lớp con từ <paramref name="parseResult"/>, connect VPN, trả tunnel đã lên.</summary>
        protected abstract Task<VpnTunnel> ConnectAsync(ParseResult parseResult, CancellationToken ct);

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
