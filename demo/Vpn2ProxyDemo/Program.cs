using System.CommandLine;
using System.Text;
using Vpn2ProxyDemo.CommandModules;

namespace Vpn2ProxyDemo
{
    // Demo: VPN -> IProxySource -> ProxyServer -> HttpClient -> checkip.amazonaws.com
    // Args xử lý bằng System.CommandLine — một command duy nhất, target VPN gói trong URI:
    //   Vpn2ProxyDemo [--vpn sstp://user:pass@host[:port]] [--check-url ... --proxy-host ... --resolve ...]
    internal static class Program
    {
        static Task<int> Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            return new CommandModule().Command.Parse(args).InvokeAsync();
        }
    }
}
