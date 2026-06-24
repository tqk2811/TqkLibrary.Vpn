using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Drivers.N2n.Config;
using TqkLibrary.VpnClient.Drivers.N2n.DataChannel;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform;
using TqkLibrary.VpnClient.N2n.Wire.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.N2n.Tests
{
    /// <summary>Unit tests for the L2 data-plane channel and the static config projection (no transport / no fabric).</summary>
    public class N2nEthernetChannelTests
    {
        static byte[] BuildEthernetFrame(MacAddress dst, MacAddress src, byte tail)
        {
            byte[] payload = new byte[20];
            payload[19] = tail;
            return EthernetFrame.Build(dst, src, EthernetFrame.EtherTypeIpv4, payload);
        }

        [Fact]
        public async Task WriteFrame_EncodesPacket_WithDestinationMacFromFrameHeader_AndCodecRoundTrips()
        {
            var codec = new N2nPacketCodec();
            var transform = new N2nNullTransform();
            MacAddress src = MacAddress.Parse("02:00:00:00:00:01");
            MacAddress dst = MacAddress.Parse("02:00:00:00:00:02");

            byte[]? sent = null;
            var channel = new N2nEthernetChannel(codec, "labnet", src.ToArray(), transform,
                (wire, ct) => { sent = wire.ToArray(); return default; });

            byte[] frame = BuildEthernetFrame(dst, src, 0x7E);
            await channel.WriteFrameAsync(frame, TestContext.Current.CancellationToken);

            Assert.NotNull(sent);
            Assert.True(codec.TryDecodePacket(sent!, transform, out _, out N2nPacket packet));
            Assert.Equal(src.ToArray(), packet.SrcMac);
            Assert.Equal(dst.ToArray(), packet.DstMac);   // dstMac read straight from the Ethernet header
            Assert.Equal(frame, packet.Payload);
        }

        [Fact]
        public void Channel_IsL2Ethernet_RequiresLinkResolution()
        {
            var channel = new N2nEthernetChannel(new N2nPacketCodec(), "labnet",
                MacAddress.Parse("02:00:00:00:00:01").ToArray(), new N2nNullTransform(), (_, _) => default);
            Assert.Equal(LinkMedium.Ethernet, channel.Medium);
            Assert.Equal(14, channel.MaxHeaderLength);
            Assert.True(channel.RequiresLinkAddressResolution);
        }

        [Fact]
        public void Deliver_RaisesInboundFrame_ForAnEthernetFrame_AndDropsRunts()
        {
            var channel = new N2nEthernetChannel(new N2nPacketCodec(), "labnet",
                MacAddress.Parse("02:00:00:00:00:01").ToArray(), new N2nNullTransform(), (_, _) => default);

            byte[]? received = null;
            channel.InboundFrame += f => received = f.ToArray();

            channel.Deliver(new byte[8]);        // runt: dropped
            Assert.Null(received);

            byte[] frame = BuildEthernetFrame(MacAddress.Parse("02:00:00:00:00:02"), MacAddress.Parse("02:00:00:00:00:01"), 0x11);
            channel.Deliver(frame);
            Assert.Equal(frame, received);
        }

        [Fact]
        public void Config_ProjectsToTunnelConfig_WithStaticAddressAndDefaultRoute()
        {
            var config = new N2nConfig
            {
                Community = "labnet",
                OverlayAddress = System.Net.IPAddress.Parse("10.7.0.2"),
                PrefixLength = 24,
            };
            var tunnel = config.ToTunnelConfig();
            Assert.Equal(System.Net.IPAddress.Parse("10.7.0.2"), tunnel.AssignedAddress);
            Assert.Equal(24, tunnel.PrefixLength);
            Assert.Contains("10.7.0.2/24", tunnel.Routes);
        }

        [Fact]
        public void Aes_Transform_RequiresKey()
        {
            var config = new N2nConfig
            {
                Community = "labnet",
                OverlayAddress = System.Net.IPAddress.Parse("10.7.0.2"),
                Transform = N2nTransformKind.Aes,
                AesKey = null,
            };
            var factory = new InProcessN2nTransportFactory(new LoopbackUdpLink().Client);
            Assert.Throws<System.ArgumentException>(() => new N2nConnection("sn", 7654, config, factory));
        }
    }
}
