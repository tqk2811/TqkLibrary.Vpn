using System.Net;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// Offline coverage for the IPV6CP negotiator (RFC 5072): Interface-Identifier negotiation drives the link-local
    /// fe80::/64 address with no live server, via a raw in-memory negotiator loopback.
    /// </summary>
    public class Ipv6cpNegotiatorTests
    {
        static readonly byte[] ClientIid = { 0x02, 0x11, 0x11, 0x11, 0xFF, 0xFE, 0x11, 0x01 };
        static readonly byte[] ServerIid = { 0x02, 0x22, 0x22, 0x22, 0xFF, 0xFE, 0x22, 0x01 };
        static readonly byte[] AssignedIid = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42 };

        [Fact]
        public void Client_AdoptsServerAssignedInterfaceId_AndDerivesLinkLocal()
        {
            var link = new NegotiatorLink();
            var client = new Ipv6cpNegotiator(link.A, ClientIid);
            var server = new Ipv6cpNegotiator(link.B, ServerIid, assignPeerInterfaceId: AssignedIid);
            link.Wire(client, server);

            bool clientOpened = false, serverOpened = false;
            client.Opened += () => clientOpened = true;
            server.Opened += () => serverOpened = true;

            client.Start();
            server.Start();
            link.Pump();

            Assert.True(clientOpened);
            Assert.True(serverOpened);
            Assert.Equal(AssignedIid, client.InterfaceId);                          // client took the server's Nak
            Assert.Equal(IPAddress.Parse("fe80::200:0:0:42"), client.LinkLocalAddress);
        }

        [Fact]
        public void DistinctIdentifiers_BothOpen_WithoutNak()
        {
            var link = new NegotiatorLink();
            var client = new Ipv6cpNegotiator(link.A, ClientIid);
            var server = new Ipv6cpNegotiator(link.B, ServerIid);            // no assignment: each keeps its own IID
            link.Wire(client, server);

            bool clientOpened = false, serverOpened = false;
            client.Opened += () => clientOpened = true;
            server.Opened += () => serverOpened = true;

            client.Start();
            server.Start();
            link.Pump();

            Assert.True(clientOpened);
            Assert.True(serverOpened);
            Assert.Equal(ClientIid, client.InterfaceId);
            Assert.Equal(ServerIid, server.InterfaceId);
        }

        [Fact]
        public void PeerRequestingCompression_IsRejected()
        {
            var sent = new List<byte[]>();
            var neg = new Ipv6cpNegotiator(p => sent.Add(p), ClientIid);

            var options = new[]
            {
                new PppOption((byte)Ipv6cpOptionType.InterfaceIdentifier, ServerIid),
                new PppOption((byte)Ipv6cpOptionType.CompressionProtocol, new byte[] { 0x00, 0x03 }),
            };
            byte[] request = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, 7, options);
            neg.HandlePacket(request);

            byte[] reply = Assert.Single(sent);
            PppControlPacket parsed = PppControlCodec.Parse(reply);
            Assert.Equal((byte)PppCode.ConfigureReject, parsed.Code);
            Assert.Equal(7, parsed.Identifier);
            PppOption rejected = Assert.Single(PppControlCodec.ParseOptions(parsed.Data));
            Assert.Equal((byte)Ipv6cpOptionType.CompressionProtocol, rejected.Type);
        }

        [Fact]
        public void ConstructorRejectsWrongLengthIdentifier()
        {
            Assert.Throws<ArgumentException>(() => new Ipv6cpNegotiator(_ => { }, new byte[7]));
            Assert.Throws<ArgumentException>(() => new Ipv6cpNegotiator(_ => { }, ClientIid, assignPeerInterfaceId: new byte[9]));
        }

        /// <summary>Wires two negotiators' send callbacks to each other's <see cref="PppNegotiator.HandlePacket"/>.</summary>
        sealed class NegotiatorLink
        {
            readonly Queue<byte[]> _toA = new();
            readonly Queue<byte[]> _toB = new();
            PppNegotiator _a = null!, _b = null!;

            public Action<byte[]> A => p => _toB.Enqueue(p); // packets A sends are delivered to B
            public Action<byte[]> B => p => _toA.Enqueue(p);

            public void Wire(PppNegotiator a, PppNegotiator b) { _a = a; _b = b; }

            public void Pump()
            {
                int guard = 0;
                while ((Deliver(_toA, _a) | Deliver(_toB, _b)) && guard++ < 1000)
                {
                }
            }

            static bool Deliver(Queue<byte[]> queue, PppNegotiator target)
            {
                if (queue.Count == 0) return false;
                target.HandlePacket(queue.Dequeue());
                return true;
            }
        }
    }
}
