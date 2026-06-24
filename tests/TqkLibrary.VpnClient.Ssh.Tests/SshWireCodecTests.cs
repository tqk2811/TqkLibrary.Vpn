using TqkLibrary.VpnClient.Ssh.Wire;
using Xunit;

namespace TqkLibrary.VpnClient.Ssh.Tests
{
    /// <summary>
    /// Unit tests for the SSH wire data-type codecs (RFC 4251 §5): byte/boolean/uint32/uint64, string, mpint (the
    /// sign-byte rules are the easiest place to break interop) and name-list. The writer and reader are each other's
    /// inverse, and the mpint encodings match the RFC 4253 §5 worked examples.
    /// </summary>
    public class SshWireCodecTests
    {
        [Fact]
        public void Integers_RoundTrip_BigEndian()
        {
            byte[] bytes = new SshWriter().WriteUInt32(0x01020304).WriteUInt64(0x0102030405060708UL).ToArray();
            Assert.Equal(new byte[] { 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8 }, bytes);

            var r = new SshReader(bytes);
            Assert.Equal(0x01020304u, r.ReadUInt32());
            Assert.Equal(0x0102030405060708UL, r.ReadUInt64());
        }

        [Fact]
        public void String_RoundTrips_LengthPrefixed()
        {
            byte[] payload = { 0xde, 0xad, 0xbe, 0xef };
            byte[] bytes = new SshWriter().WriteString(payload).ToArray();
            Assert.Equal(new byte[] { 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef }, bytes);

            var r = new SshReader(bytes);
            Assert.Equal(payload, r.ReadStringBytes());
        }

        [Fact]
        public void NameList_RoundTrips_CommaJoined()
        {
            byte[] bytes = new SshWriter().WriteNameList(new[] { "ssh-ed25519", "rsa-sha2-256" }).ToArray();
            var r = new SshReader(bytes);
            Assert.Equal(new[] { "ssh-ed25519", "rsa-sha2-256" }, r.ReadNameList());
        }

        [Fact]
        public void NameList_Empty_RoundTrips()
        {
            byte[] bytes = new SshWriter().WriteNameList(System.Array.Empty<string>()).ToArray();
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, bytes);
            var r = new SshReader(bytes);
            Assert.Empty(r.ReadNameList());
        }

        // RFC 4253 §5 mpint worked examples (the canonical interop test vectors).
        [Theory]
        // value 0 → empty string
        [InlineData(new byte[0], new byte[] { 0, 0, 0, 0 })]
        // 0x9a378f9b2e332a7 → no sign byte (high bit of 0x09 is clear)
        [InlineData(new byte[] { 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 },
                    new byte[] { 0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 })]
        // 0x80 → needs a leading 0x00 (high bit set)
        [InlineData(new byte[] { 0x80 }, new byte[] { 0, 0, 0, 2, 0x00, 0x80 })]
        public void Mpint_MatchesRfc4253Examples(byte[] magnitude, byte[] expected)
        {
            byte[] bytes = new SshWriter().WriteMpint(magnitude).ToArray();
            Assert.Equal(expected, bytes);
        }

        [Fact]
        public void Mpint_RoundTrips_TrimmingSignAndLeadingZeros()
        {
            // Magnitude with the high bit set → mpint adds 0x00 → reader strips it back to the magnitude.
            byte[] magnitude = { 0xff, 0x01, 0x02 };
            byte[] bytes = new SshWriter().WriteMpint(magnitude).ToArray();
            var r = new SshReader(bytes);
            Assert.Equal(magnitude, r.ReadMpint());
        }
    }
}
