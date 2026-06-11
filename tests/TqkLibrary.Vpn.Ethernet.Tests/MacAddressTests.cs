using TqkLibrary.Vpn.Ethernet;
using Xunit;

namespace TqkLibrary.Vpn.Ethernet.Tests
{
    public class MacAddressTests
    {
        [Fact]
        public void Parse_And_ToString_RoundTrip_LowerCaseColons()
        {
            MacAddress mac = MacAddress.Parse("AA:BB:CC:DD:EE:FF");

            Assert.Equal("aa:bb:cc:dd:ee:ff", mac.ToString());
            Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, mac.ToArray());
        }

        [Fact]
        public void Parse_AcceptsDashSeparator()
        {
            Assert.Equal(MacAddress.Parse("01:23:45:67:89:ab"), MacAddress.Parse("01-23-45-67-89-ab"));
        }

        [Theory]
        [InlineData("aa:bb:cc:dd:ee")]        // too few octets
        [InlineData("aa:bb:cc:dd:ee:ff:00")]  // too many octets
        [InlineData("aa:bb:cc:dd:ee:gg")]     // non-hex
        [InlineData("aabbccddeeff")]          // no separators
        [InlineData("a:bb:cc:dd:ee:ff")]      // single-digit octet
        [InlineData(null)]
        public void TryParse_RejectsMalformed(string? text)
        {
            Assert.False(MacAddress.TryParse(text, out _));
        }

        [Fact]
        public void Broadcast_IsBroadcast_And_IsMulticast()
        {
            MacAddress mac = MacAddress.Broadcast;

            Assert.True(mac.IsBroadcast);
            Assert.True(mac.IsMulticast);   // broadcast has the I/G bit set too
            Assert.Equal("ff:ff:ff:ff:ff:ff", mac.ToString());
            Assert.Equal(MacAddress.Parse("ff:ff:ff:ff:ff:ff"), mac);
        }

        [Fact]
        public void Multicast_IGBit_DistinguishesFromUnicast()
        {
            Assert.True(MacAddress.Parse("01:00:5e:00:00:01").IsMulticast);   // IPv4 multicast (low bit set)
            Assert.False(MacAddress.Parse("00:11:22:33:44:55").IsMulticast);  // unicast (low bit clear)
            Assert.False(MacAddress.Parse("00:11:22:33:44:55").IsBroadcast);
        }

        [Fact]
        public void IsIpv6Multicast_OnlyForThe3333Prefix()
        {
            Assert.True(MacAddress.Parse("33:33:00:00:00:01").IsIpv6Multicast);   // solicited-node style
            Assert.True(MacAddress.Parse("33:33:ff:ab:cd:ef").IsIpv6Multicast);
            Assert.False(MacAddress.Parse("33:00:00:00:00:01").IsIpv6Multicast);  // second octet not 0x33
            Assert.False(MacAddress.Parse("01:00:5e:00:00:01").IsIpv6Multicast);  // IPv4 multicast, not v6
        }

        [Fact]
        public void FromBytes_CopyTo_RoundTrip()
        {
            byte[] octets = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x42 };
            MacAddress mac = MacAddress.FromBytes(octets);

            Span<byte> buffer = stackalloc byte[6];
            mac.CopyTo(buffer);
            Assert.Equal(octets, buffer.ToArray());
            Assert.Equal(octets, mac.ToArray());
        }

        [Fact]
        public void FromBytes_WrongLength_Throws()
        {
            Assert.Throws<ArgumentException>(() => MacAddress.FromBytes(new byte[5]));
            Assert.Throws<ArgumentException>(() => MacAddress.FromBytes(new byte[7]));
        }

        [Fact]
        public void Equality_And_HashCode_MatchOnValue()
        {
            MacAddress a = MacAddress.Parse("00:11:22:33:44:55");
            MacAddress b = MacAddress.FromBytes(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 });
            MacAddress c = MacAddress.Parse("00:11:22:33:44:56");

            Assert.True(a == b);
            Assert.False(a != b);
            Assert.Equal(a.GetHashCode(), b.GetHashCode());
            Assert.True(a != c);
            Assert.NotEqual(a, c);

            // Usable as a dictionary key (the L2.1 FDB relies on this).
            var fdb = new Dictionary<MacAddress, int> { [a] = 1 };
            Assert.True(fdb.ContainsKey(b));
            Assert.False(fdb.ContainsKey(c));
        }

        [Fact]
        public void Zero_IsNeitherBroadcastNorMulticast()
        {
            Assert.Equal("00:00:00:00:00:00", MacAddress.Zero.ToString());
            Assert.False(MacAddress.Zero.IsBroadcast);
            Assert.False(MacAddress.Zero.IsMulticast);
        }
    }
}
