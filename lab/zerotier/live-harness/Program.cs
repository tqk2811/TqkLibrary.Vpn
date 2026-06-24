// V.7.3 ZeroTier driver-runtime live harness. Drives the real ZeroTierConnection against a live zerotier-one
// controller node: VL1 HELLO ⇄ OK, VL2 NETWORK_CONFIG_REQUEST (assigned IP + COM), then an ICMP echo to the
// gateway over the VL2 EXT_FRAME L2 overlay. Clean-room: only this project's driver/codec, no ZeroTier source.
//
// Usage: zt-live-harness <clientSecretPath> <nodePublicPath> <host> <port> <networkIdHex> [gatewayIp]

using System.Net;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Drivers.ZeroTier;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

if (args.Length < 5)
{
    Console.Error.WriteLine("usage: zt-live-harness <clientSecret> <nodePublic> <host> <port> <networkIdHex> [gatewayIp]");
    return 2;
}

var idCodec = new ZeroTierIdentityCodec();
var client = idCodec.ParseString(File.ReadAllText(args[0]).Trim());
var node = idCodec.ParseString(File.ReadAllText(args[1]).Trim());
string host = args[2];
int port = int.Parse(args[3]);
var network = NetworkId.Parse(args[4].Trim());
IPAddress gateway = IPAddress.Parse(args.Length > 5 ? args[5] : "10.144.0.1");

if (!client.HasPrivate) { Console.Error.WriteLine("client identity has no private key"); return 2; }

Console.WriteLine($"[harness] client  = {client.Address}");
Console.WriteLine($"[harness] node    = {node.Address} @ {host}:{port}");
Console.WriteLine($"[harness] network = {network}  (controller = {network.ControllerAddress:x10})");

using var loggerFactory = LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Trace).AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; }));

var config = new ZeroTierConfig
{
    Identity = client,
    PeerIdentity = node,
    NetworkId = network,
    OverlayAddress = null,             // adopt the controller-assigned IP
    NetworkConfigTimeout = TimeSpan.FromSeconds(20),
};

var factory = new TqkLibrary.VpnClient.Drivers.ZeroTier.Transport.ZeroTierSocketTransportFactory();
var vpn = new ZeroTierConnection(host, port, config, factory,
    reconnectOptions: new ZeroTierReconnectOptions { Enabled = false }, loggerFactory: loggerFactory);

try
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
    Console.WriteLine("[harness] connecting (HELLO/OK + NETWORK_CONFIG) ...");
    await vpn.ConnectAsync(cts.Token);

    IPAddress assigned = vpn.AssignedAddress;
    Console.WriteLine($"[harness] *** CONNECTED *** overlay IP = {assigned}, mtu = {vpn.PacketChannel.Mtu}");

    var stack = new TcpIpStack(vpn.PacketChannel, assigned);
    Console.WriteLine($"[harness] pinging gateway {gateway} over the VL2 overlay ...");
    for (int i = 0; i < 4; i++)
    {
        try
        {
            using var pingCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            PingReply reply = await stack.PingAsync(gateway, default, pingCts.Token);
            Console.WriteLine($"[harness] *** ICMP REPLY from {reply.RemoteAddress} rtt={reply.RoundTripTime.TotalMilliseconds:F1}ms ***");
            Console.WriteLine("[harness] RESULT: ZEROTIER L2 TUNNEL LIVE — HELLO/OK + network join + ICMP 2-way over VL2.");
            await vpn.DisposeAsync();
            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cts.IsCancellationRequested)
        {
            Console.WriteLine($"[harness] ping {i + 1} no reply ({ex.GetType().Name})");
        }
        await Task.Delay(1000, cts.Token);
    }

    Console.WriteLine("[harness] RESULT: VL1 + network-join SUCCEEDED, but no ICMP reply (gateway/route issue).");
    await vpn.DisposeAsync();
    return 1;
}
catch (Exception ex)
{
    Console.WriteLine($"[harness] FAILED: {ex.GetType().Name}: {ex.Message}");
    try { await vpn.DisposeAsync(); } catch { }
    return 1;
}
