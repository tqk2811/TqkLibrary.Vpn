using System.CommandLine;
using System.Diagnostics;
using System.Net;
using System.Net.Http;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Subcommand <c>http-post-upload</c>: kế thừa <see cref="ProxyServerCommandModule"/> (dựng proxy local qua tunnel),
    /// nhưng thay vì giữ tới khi nhấn Enter thì <b>POST một payload lớn</b> (<c>--size</c> byte) tới một URL (<c>--url</c>)
    /// <b>qua proxy</b> đó, in throughput + byte server xác nhận rồi <b>thoát luôn</b>.
    /// <para>
    /// Dùng để re-validate live fix Q.4 (sender-side Silly-Window-Syndrome avoidance trong
    /// <c>TqkLibrary.VpnClient.IpStack.Tcp.TcpConnection</c>): upload HTTP lớn qua tunnel phải <b>hoàn tất với throughput
    /// bình thường</b> — không còn rơi vào "1 byte/segment". Đường gửi đi qua proxy → <c>VpnProxySource</c> → userspace
    /// <c>TcpConnection</c> (nơi nằm fix), nên đo được hành vi sender-side SWS thật end-to-end.
    /// </para>
    /// </summary>
    internal sealed class HttpPostUploadProxyServerCommandModule : ProxyServerCommandModule
    {
        Option<string> UrlOption { get; }
        Option<int> SizeOption { get; }

        public HttpPostUploadProxyServerCommandModule()
            : base("http-post-upload", "POST một payload lớn qua proxy trong tunnel (re-validate Q.4 SWS) rồi in throughput và thoát.")
        {
            UrlOption = new Option<string>("--url")
            {
                Description = "URL để POST payload lớn qua proxy (qua tunnel). Server đếm byte body nhận được.",
                DefaultValueFactory = _ => "http://10.60.0.1:8081/upload",
            };
            SizeOption = new Option<int>("--size")
            {
                Description = "Số byte payload upload (mặc định 10 MB). Đủ lớn để vượt cwnd ban đầu nhiều lần — phơi bày stall SWS nếu còn.",
                DefaultValueFactory = _ => 10 * 1024 * 1024,
            };
            Command.Options.Add(UrlOption);
            Command.Options.Add(SizeOption);
        }

        protected override string? ValidateOptions(ParseResult parseResult)
        {
            string? baseError = base.ValidateOptions(parseResult);
            if (baseError != null) return baseError;
            int size = parseResult.GetValue(SizeOption);
            if (size <= 0) return $"--size {size} phải là số byte dương.";
            return null;
        }

        protected override async Task OnProxyReadyAsync(string tag, string clientProxyUrl, string displayUrl, ParseResult parseResult, CancellationToken ct)
        {
            string url = parseResult.GetValue(UrlOption)!;
            int size = parseResult.GetValue(SizeOption);
            Console.WriteLine($"[{tag}] POST {size:N0} byte tới {url} qua proxy {clientProxyUrl} ...");
            try
            {
                using var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy(clientProxyUrl),
                    UseProxy = true,
                };
                // Timeout rộng: nếu fix Q.4 hỏng, upload kẹt "1 byte/segment" sẽ timeout ở đây thay vì treo vô hạn.
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(120) };

                // Payload xác định (không nén được trên đường, nhưng HTTP không nén POST mặc định): mảng byte cố định.
                byte[] payload = new byte[size];
                for (int i = 0; i < size; i++) payload[i] = (byte)(i & 0xFF);

                var content = new ByteArrayContent(payload);
                content.Headers.ContentLength = size; // Content-Length tường minh ⇒ server biết khi nào đọc đủ

                var sw = Stopwatch.StartNew();
                using HttpResponseMessage resp = await http.PostAsync(url, content, ct);
                string body = (await resp.Content.ReadAsStringAsync(ct)).Trim();
                sw.Stop();

                double mb = size / (1024.0 * 1024.0);
                double secs = sw.Elapsed.TotalSeconds;
                double mbps = secs > 0 ? mb / secs : 0;
                Console.WriteLine($"[{tag}] => HTTP {(int)resp.StatusCode} sau {secs:F2}s — {mb:F2} MB ⇒ {mbps:F2} MB/s. Server: {body}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{tag}] POST lỗi: {ex.GetType().Name}: {ex.Message}");
            }
            // Không chờ Enter — in kết quả xong thoát luôn.
        }
    }
}
