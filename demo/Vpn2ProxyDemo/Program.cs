using System.CommandLine;
using System.Text;
using Vpn2ProxyDemo.CommandModules;

namespace Vpn2ProxyDemo
{
    // Demo: VPN -> IProxySource -> ProxyServer -> HttpClient -> checkip.amazonaws.com
    // System.CommandLine: mỗi hành động là một subcommand, target VPN gói trong URI --vpn:
    //   Vpn2ProxyDemo dns          --vpn sstp://user:pass@host[:port]            (probe UDP-DNS qua tunnel)
    //   Vpn2ProxyDemo proxy-server --vpn l2tp://user:pass@host[:port]            (dựng proxy, giữ tới khi nhấn Enter)
    //   Vpn2ProxyDemo http-request --vpn sstp://user:pass@host[:port] --url ...  (GET url qua proxy rồi thoát)
    internal static class Program
    {
        static Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            var root = new RootCommand("Demo: VPN (MS-SSTP / L2TP-IPsec) -> IProxySource -> ProxyServer -> HttpClient -> checkip.")
            {
                new ProbeUdpDnsCommandModule().Command,
                new ProxyServerCommandModule().Command,
                new HttpRequestProxyServerCommandModule().Command,
                new HttpPostUploadProxyServerCommandModule().Command,
            };

            return root.Parse(args).InvokeAsync();
        }
    }
}
