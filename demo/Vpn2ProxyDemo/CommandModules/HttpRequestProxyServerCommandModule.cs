using System.CommandLine;
using System.Net;
using System.Net.Http;

namespace Vpn2ProxyDemo.CommandModules
{
    /// <summary>
    /// Subcommand <c>http-request</c>: kế thừa <see cref="ProxyServerCommandModule"/> (dựng proxy local qua tunnel), nhưng
    /// thay vì giữ tới khi nhấn Enter thì GET một URL (<c>--url</c>) <b>qua proxy</b> đó, in response body rồi <b>thoát luôn</b>.
    /// Dùng để kiểm nhanh đường đi HTTP qua VPN (vd checkip thấy IP công cộng của VPN server).
    /// </summary>
    internal sealed class HttpRequestProxyServerCommandModule : ProxyServerCommandModule
    {
        Option<string> UrlOption { get; }

        public HttpRequestProxyServerCommandModule()
            : base("http-request", "GET một URL qua proxy trong tunnel rồi in kết quả và thoát.")
        {
            UrlOption = new Option<string>("--url")
            {
                Description = "URL để GET qua proxy (qua tunnel). In response body rồi thoát.",
                DefaultValueFactory = _ => "https://checkip.amazonaws.com/",
            };
            Command.Options.Add(UrlOption);
        }

        protected override async Task OnProxyReadyAsync(string tag, string clientProxyUrl, string displayUrl, ParseResult parseResult, CancellationToken ct)
        {
            string url = parseResult.GetValue(UrlOption)!;
            Console.WriteLine($"[{tag}] GET {url} qua proxy {clientProxyUrl} ...");
            try
            {
                using var handler = new HttpClientHandler
                {
                    Proxy = new WebProxy(clientProxyUrl),
                    UseProxy = true,
                };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(40) };

                string body = (await http.GetStringAsync(url, ct)).Trim();
                Console.WriteLine($"[{tag}] => {body}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[{tag}] GET lỗi: {ex.GetType().Name}: {ex.Message}");
            }
            // Không chờ Enter — in kết quả xong thoát luôn.
        }
    }
}
