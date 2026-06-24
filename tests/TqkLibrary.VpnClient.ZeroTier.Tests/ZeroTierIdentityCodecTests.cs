using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    public class ZeroTierIdentityCodecTests
    {
        static byte[] Pattern(int len, byte seed)
        {
            byte[] b = new byte[len];
            for (int i = 0; i < len; i++) b[i] = (byte)(i * 7 + seed);
            return b;
        }

        static ZeroTierIdentity Sample(bool withPrivate)
        {
            return new ZeroTierIdentity
            {
                Address = ZeroTierAddress.Parse("8056c2e21c"),
                PublicKey = Pattern(64, 1),
                PrivateKey = withPrivate ? Pattern(64, 200) : null,
            };
        }

        readonly ZeroTierIdentityCodec _codec = new ZeroTierIdentityCodec();

        [Fact]
        public void StringForm_PublicOnly_RoundTrips()
        {
            var id = Sample(withPrivate: false);
            string s = _codec.ToString(id, includePrivate: false);

            Assert.StartsWith("8056c2e21c:0:", s);
            var parsed = _codec.ParseString(s);
            Assert.Equal(id.Address, parsed.Address);
            Assert.Equal(id.PublicKey, parsed.PublicKey);
            Assert.False(parsed.HasPrivate);
        }

        [Fact]
        public void StringForm_WithPrivate_RoundTrips()
        {
            var id = Sample(withPrivate: true);
            string s = _codec.ToString(id, includePrivate: true);

            var parsed = _codec.ParseString(s);
            Assert.Equal(id.PublicKey, parsed.PublicKey);
            Assert.True(parsed.HasPrivate);
            Assert.Equal(id.PrivateKey, parsed.PrivateKey);
        }

        [Fact]
        public void BinaryForm_RoundTrips_PublicAndPrivate()
        {
            foreach (bool priv in new[] { false, true })
            {
                var id = Sample(priv);
                byte[] bin = _codec.EncodeBinary(id, includePrivate: priv);
                Assert.True(_codec.TryDecodeBinary(bin, out var parsed));
                Assert.Equal(id.Address, parsed.Address);
                Assert.Equal(id.PublicKey, parsed.PublicKey);
                Assert.Equal(priv, parsed.HasPrivate);
                if (priv) Assert.Equal(id.PrivateKey, parsed.PrivateKey);
            }
        }

        [Fact]
        public void ParseString_RejectsUnsupportedTypeAndBadLengths()
        {
            Assert.Throws<FormatException>(() => _codec.ParseString("8056c2e21c:1:00")); // type 1 unsupported
            Assert.Throws<FormatException>(() => _codec.ParseString("8056c2e21c:0:00")); // pubkey too short
            Assert.Throws<FormatException>(() => _codec.ParseString("nope"));            // missing fields
        }

        [Fact]
        public void TryDecodeBinary_RejectsShortBuffer()
        {
            Assert.False(_codec.TryDecodeBinary(new byte[10], out _));
        }
    }
}
