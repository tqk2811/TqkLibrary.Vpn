using TqkLibrary.VpnClient.Ssh.Channel;
using TqkLibrary.VpnClient.Ssh.Channel.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Ssh.Tests
{
    /// <summary>
    /// Tests for the tun@openssh.com layer-3 framing (PROTOCOL §2.3): inside the SSH channel-data string a bare IP packet
    /// wraps to <c>uint32 address_family || ip</c> with the address family chosen from the IP version nibble
    /// (IPv4 = 2, IPv6 = 24). Decapsulation is the inverse, and rejects framing too short to hold the 4-byte AF. (The
    /// AF-only layout — no extra packet_length field — was confirmed live against OpenSSH on Linux.)
    /// </summary>
    public class SshTunFramingTests
    {
        [Fact]
        public void Encapsulate_Ipv4_HasAfInet()
        {
            byte[] ip = new byte[20]; ip[0] = 0x45; // IPv4 version+IHL
            byte[] framed = SshTunFraming.Encapsulate(ip);

            // address family field = AF_INET (2), then the bare IP packet.
            Assert.Equal(new byte[] { 0, 0, 0, (byte)SshTunAddressFamily.Inet }, framed.AsSpan(0, 4).ToArray());
            Assert.Equal(4 + 20, framed.Length);
        }

        [Fact]
        public void Encapsulate_Ipv6_HasAfInet6()
        {
            byte[] ip = new byte[40]; ip[0] = 0x60; // IPv6 version nibble
            byte[] framed = SshTunFraming.Encapsulate(ip);
            Assert.Equal((byte)SshTunAddressFamily.Inet6, framed[3]);
        }

        [Fact]
        public void Encapsulate_Decapsulate_RoundTrips()
        {
            byte[] ip = new byte[60];
            for (int i = 0; i < ip.Length; i++) ip[i] = (byte)(i + 1);
            ip[0] = 0x45;

            byte[] framed = SshTunFraming.Encapsulate(ip);
            Assert.True(SshTunFraming.TryDecapsulate(framed, out var recovered, out var af));
            Assert.Equal(ip, recovered.ToArray());
            Assert.Equal(SshTunAddressFamily.Inet, af);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(3)]
        public void Decapsulate_TooShort_ReturnsFalse(int len)
        {
            byte[] tooShort = new byte[len];
            Assert.False(SshTunFraming.TryDecapsulate(tooShort, out _, out _));
        }

        [Fact]
        public void Decapsulate_AfOnly_EmptyIpPacket()
        {
            // exactly 4 bytes (AF only, no IP) → decapsulates to an empty IP packet.
            byte[] framed = { 0, 0, 0, (byte)SshTunAddressFamily.Inet };
            Assert.True(SshTunFraming.TryDecapsulate(framed, out var ip, out var af));
            Assert.Equal(0, ip.Length);
            Assert.Equal(SshTunAddressFamily.Inet, af);
        }
    }
}
