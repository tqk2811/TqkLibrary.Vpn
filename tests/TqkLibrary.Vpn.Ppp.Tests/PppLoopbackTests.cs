using System.Net;
using TqkLibrary.Vpn.Ppp;
using Xunit;

namespace TqkLibrary.Vpn.Ppp.Tests
{
    public class PppLoopbackTests
    {
        static readonly IPAddress ClientIp = IPAddress.Parse("10.0.0.2");
        static readonly IPAddress ServerIp = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress Dns = IPAddress.Parse("8.8.8.8");

        [Fact]
        public void TwoEngines_NegotiateLcpAndIpcp_ClientGetsAssignedAddress()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp, assignPeerAddress: ClientIp, assignPeerDns: Dns);

            bool clientUp = false;
            client.LinkUp += () => clientUp = true;

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(clientUp);
            Assert.True(server.IsLinkUp);
            Assert.Equal(ClientIp, client.AssignedAddress);
            Assert.Equal(Dns, client.AssignedDns);
            Assert.Equal(ServerIp, server.AssignedAddress);
        }

        [Fact]
        public void TwoEngines_DualStack_ClientGetsIpv4AndLinkLocalIpv6()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            byte[] assignedIid = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42 };

            var client = new PppEngine(ca, magic: 0x11111111, localAddress: IPAddress.Any, enableIpv6: true);
            var server = new PppEngine(cb, magic: 0x22222222, localAddress: ServerIp,
                assignPeerAddress: ClientIp, assignPeerDns: Dns,
                enableIpv6: true, assignPeerInterfaceId: assignedIid);

            bool v4 = false, v6 = false;
            client.LinkUp += () => v4 = true;
            client.Ipv6Up += () => v6 = true;

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);

            Assert.True(v4);                                       // IPCP unaffected by enabling IPv6
            Assert.True(v6);
            Assert.Equal(ClientIp, client.AssignedAddress);
            Assert.Equal(IPAddress.Parse("fe80::200:0:0:42"), client.AssignedAddressV6);
            Assert.True(server.IsIpv6Up);
        }

        [Fact]
        public void AfterLinkUp_IpPacketIsRelayed()
        {
            var (ca, cb) = LoopbackPppChannel.CreatePair();
            var client = new PppEngine(ca, 0x11111111, IPAddress.Any);
            var server = new PppEngine(cb, 0x22222222, ServerIp, ClientIp, Dns);

            client.Start();
            server.Start();
            LoopbackPppChannel.Pump(ca, cb);
            Assert.True(client.IsLinkUp);

            byte[]? received = null;
            server.PacketChannel.InboundIpPacket += p => received = p.ToArray();

            // A minimal 20-byte IPv4 header (content is opaque to PPP — it just relays).
            byte[] ipPacket =
            {
                0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
                0x40, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x02,
                0x0A, 0x00, 0x00, 0x01,
            };

            client.PacketChannel.WriteIpPacketAsync(ipPacket);
            LoopbackPppChannel.Pump(ca, cb);

            Assert.Equal(ipPacket, received);
        }
    }
}
