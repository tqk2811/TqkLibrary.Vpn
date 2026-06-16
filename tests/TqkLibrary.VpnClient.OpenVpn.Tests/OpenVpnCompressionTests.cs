using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.f compression stub framing (no actual compression): round-trip for each mode, that a genuinely
    /// compressed packet is rejected, and the PUSH_REPLY directive → mode mapping.
    /// </summary>
    public class OpenVpnCompressionTests
    {
        static readonly byte[] Ip = { 0x45, 0x00, 0x00, 0x28, 0xDE, 0xAD }; // looks like an IPv4 header start

        [Theory]
        [InlineData(OpenVpnCompression.Mode.None)]
        [InlineData(OpenVpnCompression.Mode.CompLzo)]
        [InlineData(OpenVpnCompression.Mode.StubV2)]
        public void WrapThenUnwrap_RoundTrips(OpenVpnCompression.Mode mode)
        {
            var comp = new OpenVpnCompression(mode);
            byte[] framed = comp.WrapOutgoing(Ip);
            Assert.True(comp.TryUnwrapIncoming(framed, out byte[] ip));
            Assert.Equal(Ip, ip);
        }

        [Fact]
        public void CompLzo_AddsOneNoCompressByte_AndRejectsCompressed()
        {
            var comp = new OpenVpnCompression(OpenVpnCompression.Mode.CompLzo);
            byte[] framed = comp.WrapOutgoing(Ip);
            Assert.Equal(Ip.Length + 1, framed.Length);
            Assert.Equal(0xFA, framed[0]);

            byte[] compressed = new byte[] { 0x66, 1, 2, 3 }; // LZO-compressed marker
            Assert.False(comp.TryUnwrapIncoming(compressed, out _));
            Assert.False(comp.TryUnwrapIncoming(Array.Empty<byte>(), out _));
        }

        [Fact]
        public void StubV2_ZeroOverheadForIp_ButEscapesIndicatorByte()
        {
            var comp = new OpenVpnCompression(OpenVpnCompression.Mode.StubV2);

            // Normal IP packet: no byte added.
            Assert.Equal(Ip, comp.WrapOutgoing(Ip));

            // A packet whose first byte is the 0x50 indicator must be escaped, then recovered.
            byte[] collide = { 0x50, 0x11, 0x22 };
            byte[] framed = comp.WrapOutgoing(collide);
            Assert.Equal(collide.Length + 2, framed.Length);
            Assert.True(comp.TryUnwrapIncoming(framed, out byte[] got));
            Assert.Equal(collide, got);

            // A genuinely compressed v2 packet (indicator + non-uncompressed op) is rejected.
            Assert.False(comp.TryUnwrapIncoming(new byte[] { 0x50, 0x01, 0xAA }, out _));
        }

        [Theory]
        [InlineData("comp-lzo no", OpenVpnCompression.Mode.CompLzo)]
        [InlineData("comp-lzo", OpenVpnCompression.Mode.CompLzo)]
        [InlineData("compress stub-v2", OpenVpnCompression.Mode.StubV2)]
        [InlineData("compress", OpenVpnCompression.Mode.StubV2)]
        public void FromPushReply_MapsDirectiveToMode(string directive, OpenVpnCompression.Mode expected)
        {
            Assert.True(OpenVpnPushReply.TryParse($"PUSH_REPLY,{directive},ifconfig 10.8.0.6 255.255.255.0", out OpenVpnPushReply reply));
            Assert.Equal(expected, OpenVpnCompression.FromPushReply(reply).Framing);
        }

        [Fact]
        public void FromPushReply_NoDirective_IsNone()
        {
            Assert.True(OpenVpnPushReply.TryParse("PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0", out OpenVpnPushReply reply));
            Assert.Equal(OpenVpnCompression.Mode.None, OpenVpnCompression.FromPushReply(reply).Framing);
        }
    }
}
