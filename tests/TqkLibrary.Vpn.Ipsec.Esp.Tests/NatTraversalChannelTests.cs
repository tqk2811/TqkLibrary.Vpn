using System.Net;
using System.Net.Sockets;
using TqkLibrary.Vpn.Ipsec.Nat;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Esp.Tests
{
    /// <summary>
    /// Offline checks that the NAT-T UDP channel binds in the gateway's address family — the outer-IPv6 path (P1.2).
    /// No live gateway: only the local socket bind + route probe are exercised.
    /// </summary>
    public class NatTraversalChannelTests
    {
        [Fact]
        public async Task IPv4Gateway_BindsIPv4Socket_AndProbesIPv4LocalAddress()
        {
            await using var channel = new NatTraversalChannel(IPAddress.Loopback);

            Assert.True(channel.LocalPort > 0);                                  // an ephemeral port was bound
            Assert.Equal(AddressFamily.InterNetwork, channel.GetLocalAddress().AddressFamily);
        }

        [Fact]
        public async Task IPv6Gateway_BindsIPv6Socket_AndProbesIPv6LocalAddress()
        {
            await using var channel = new NatTraversalChannel(IPAddress.IPv6Loopback);

            Assert.True(channel.LocalPort > 0);                                  // bound in the IPv6 family (would throw if forced IPv4)
            Assert.Equal(AddressFamily.InterNetworkV6, channel.GetLocalAddress().AddressFamily);
        }
    }
}
