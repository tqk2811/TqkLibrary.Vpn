using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class InMemoryEthernetChannelTests
    {
        [Fact]
        public void Channel_ExposesL2LinkProperties()
        {
            MacAddress mac = MacAddress.Parse("02:00:00:00:00:01");
            var pair = new EthernetLoopbackPair(mac, MacAddress.Parse("02:00:00:00:00:02"));

            Assert.Equal(LinkMedium.Ethernet, pair.A.Medium);
            Assert.Equal(EthernetFrame.HeaderLength, pair.A.MaxHeaderLength);
            Assert.True(pair.A.RequiresLinkAddressResolution);
            Assert.Equal(mac.ToArray(), pair.A.LinkAddress.ToArray());
            Assert.True(pair.A.Mtu > 0);
        }

        [Fact]
        public async Task WriteFrame_OnOneEnd_RaisesInboundFrame_OnTheOther()
        {
            MacAddress macA = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress macB = MacAddress.Parse("02:00:00:00:00:02");
            var pair = new EthernetLoopbackPair(macA, macB);

            byte[]? received = null;
            pair.B.InboundFrame += frame => received = frame.ToArray();

            byte[] sent = EthernetFrame.Build(macB, macA, EthernetFrame.EtherTypeIpv4, new byte[] { 1, 2, 3, 4 });
            await pair.A.WriteFrameAsync(sent);

            Assert.NotNull(received);
            Assert.Equal(sent, received);
            Assert.Equal(macB, EthernetFrame.Destination(received));
            Assert.Equal(macA, EthernetFrame.Source(received));
        }

        /// <summary>Two in-memory <see cref="IEthernetChannel"/> endpoints wired back to back (A writes → B's inbound, and vice versa).</summary>
        sealed class EthernetLoopbackPair
        {
            public EthernetLoopbackPair(MacAddress macA, MacAddress macB)
            {
                var a = new Endpoint(macA);
                var b = new Endpoint(macB);
                a.Peer = b;
                b.Peer = a;
                A = a;
                B = b;
            }

            public IEthernetChannel A { get; }
            public IEthernetChannel B { get; }

            sealed class Endpoint : IEthernetChannel
            {
                readonly byte[] _mac;
                public Endpoint? Peer;
                public Endpoint(MacAddress mac) => _mac = mac.ToArray();

                public LinkMedium Medium => LinkMedium.Ethernet;
                public int Mtu => 1500;
                public int MaxHeaderLength => EthernetFrame.HeaderLength;
                public bool RequiresLinkAddressResolution => true;
                public ReadOnlyMemory<byte> LinkAddress => _mac;
                public event Action<ReadOnlyMemory<byte>>? InboundFrame;

                public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
                {
                    byte[] copy = ethernetFrame.ToArray();
                    Peer?.InboundFrame?.Invoke(copy);
                    return default;
                }

                public ValueTask DisposeAsync() => default;
            }
        }
    }
}
