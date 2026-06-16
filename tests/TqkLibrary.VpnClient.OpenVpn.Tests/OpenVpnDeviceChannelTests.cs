using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Transport;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.g device-link bridges: tun presents the data channel as an L3 <c>IPacketChannel</c> (bare IP, no
    /// MAC), tap as an L2 <c>IEthernetChannel</c> (Ethernet frame, 14-byte header, link-address resolution). Both ride
    /// the same AEAD data channel + compression framing, so a payload written on the client comes out intact on the
    /// server's matching channel of the same kind.
    /// </summary>
    public class OpenVpnDeviceChannelTests
    {
        // A matched client+server data-channel pair (same key2), as in OpenVpnDataPlaneTests.
        static (OpenVpnDataChannel client, OpenVpnDataChannel server) Pair(byte seed)
        {
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(seed + i); r2[i] = (byte)(seed * 2 + i); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);
            var clientKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.DeriveDataKeys(clientKs, serverKs, 0xAAAA, 0xBBBB, isServer: true);
            return (new OpenVpnDataChannel(clientKeys), new OpenVpnDataChannel(serverKeys));
        }

        [Fact]
        public void TunChannel_ExposesL3Metadata()
        {
            var (c, _) = Pair(0x11);
            var tun = new OpenVpnTunChannel(new OpenVpnDataPlane(c), new OpenVpnCompression(OpenVpnCompression.Mode.None), _ => default, mtu: 1400);
            Assert.Equal(LinkMedium.Ip, tun.Medium);
            Assert.Equal(0, tun.MaxHeaderLength);
            Assert.False(tun.RequiresLinkAddressResolution);
            Assert.Equal(1400, tun.Mtu);
        }

        [Fact]
        public void TapChannel_ExposesL2Metadata_AndRejectsBadMac()
        {
            var (c, _) = Pair(0x12);
            byte[] mac = { 0x02, 0x00, 0x00, 0x11, 0x22, 0x33 };
            var tap = new OpenVpnTapChannel(new OpenVpnDataPlane(c), new OpenVpnCompression(OpenVpnCompression.Mode.None), _ => default, mac);
            Assert.Equal(LinkMedium.Ethernet, tap.Medium);
            Assert.Equal(14, tap.MaxHeaderLength);
            Assert.True(tap.RequiresLinkAddressResolution);
            Assert.Equal(mac, tap.LinkAddress.ToArray());

            Assert.Throws<ArgumentException>(() =>
                new OpenVpnTapChannel(new OpenVpnDataPlane(c), new OpenVpnCompression(OpenVpnCompression.Mode.None), _ => default, new byte[5]));
        }

        [Fact]
        public async Task TunChannel_RoundTripsIpPacket_OverDataChannel()
        {
            var (c, s) = Pair(0x21);
            // Client tun seals into a wire packet captured by the sink; the server tun delivers it back as a payload.
            byte[]? wire = null;
            var clientTun = new OpenVpnTunChannel(new OpenVpnDataPlane(c), new OpenVpnCompression(OpenVpnCompression.Mode.StubV2), m => { wire = m.ToArray(); return default; });
            var serverTun = new OpenVpnTunChannel(new OpenVpnDataPlane(s), new OpenVpnCompression(OpenVpnCompression.Mode.StubV2), _ => default);
            var inbound = new List<byte[]>();
            serverTun.InboundIpPacket += m => inbound.Add(m.ToArray());

            byte[] ip = Encoding.ASCII.GetBytes("an IP packet payload");
            await clientTun.WriteIpPacketAsync(ip);
            Assert.NotNull(wire);
            serverTun.Deliver(wire!);

            Assert.Single(inbound);
            Assert.Equal(ip, inbound[0]);
        }

        [Fact]
        public async Task TapChannel_RoundTripsEthernetFrame_OverDataChannel()
        {
            var (c, s) = Pair(0x22);
            byte[] clientMac = { 0x02, 0, 0, 0, 0, 0x01 }, serverMac = { 0x02, 0, 0, 0, 0, 0x02 };
            byte[]? wire = null;
            var clientTap = new OpenVpnTapChannel(new OpenVpnDataPlane(c), new OpenVpnCompression(OpenVpnCompression.Mode.None), m => { wire = m.ToArray(); return default; }, clientMac);
            var serverTap = new OpenVpnTapChannel(new OpenVpnDataPlane(s), new OpenVpnCompression(OpenVpnCompression.Mode.None), _ => default, serverMac);
            var inbound = new List<byte[]>();
            serverTap.InboundFrame += m => inbound.Add(m.ToArray());

            // A minimal Ethernet frame: dst MAC | src MAC | ethertype (0x0800 = IPv4) | payload.
            byte[] frame = new byte[14 + 4];
            serverMac.CopyTo(frame, 0);
            clientMac.CopyTo(frame, 6);
            frame[12] = 0x08; frame[13] = 0x00;
            frame[14] = 0xDE; frame[15] = 0xAD; frame[16] = 0xBE; frame[17] = 0xEF;

            await clientTap.WriteFrameAsync(frame);
            Assert.NotNull(wire);
            serverTap.Deliver(wire!);

            Assert.Single(inbound);
            Assert.Equal(frame, inbound[0]);
        }

        [Fact]
        public void Deliver_DropsPacketSealedForADifferentKey()
        {
            var (_, s) = Pair(0x31);
            var (cOther, _) = Pair(0x99); // unrelated key generation
            byte[] alien = new OpenVpnDataPlane(cOther).Protect(new byte[] { 1, 2, 3 });

            var serverTun = new OpenVpnTunChannel(new OpenVpnDataPlane(s), new OpenVpnCompression(OpenVpnCompression.Mode.None), _ => default);
            bool raised = false;
            serverTun.InboundIpPacket += _ => raised = true;

            serverTun.Deliver(alien); // wrong key ⇒ GCM tag fails ⇒ no event
            Assert.False(raised);
        }
    }
}
