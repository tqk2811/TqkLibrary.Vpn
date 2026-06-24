using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    /// <summary>
    /// Tests for the memory-hard address derivation. These assert <b>self-consistency and structure</b> only — the
    /// byte-exact output has NOT been cross-checked against a real zerotier-idtool identity (no offline sample vector,
    /// VM lab down). When the lab is up, add a KAT here from a known idtool identity to confirm interop.
    /// </summary>
    public class ZeroTierAddressDerivationTests
    {
        static byte[] PublicKey(byte seed)
        {
            byte[] b = new byte[ZeroTierIdentity.PublicKeySize];
            for (int i = 0; i < b.Length; i++) b[i] = (byte)(i * 13 + seed);
            return b;
        }

        readonly ZeroTierAddressDerivation _derive = new ZeroTierAddressDerivation();

        [Fact]
        public void Derivation_IsDeterministic_ForTheSameKey()
        {
            byte[] pub = PublicKey(5);
            bool ok1 = _derive.TryComputeDigest(pub, out byte[] d1, out var a1);
            bool ok2 = _derive.TryComputeDigest(pub, out byte[] d2, out var a2);

            Assert.Equal(ok1, ok2);
            Assert.Equal(d1, d2);
            Assert.Equal(a1, a2);
            Assert.Equal(64, d1.Length);
        }

        [Fact]
        public void Address_IsLastFiveBytesOfDigest()
        {
            byte[] pub = PublicKey(9);
            _derive.TryComputeDigest(pub, out byte[] digest, out var address);

            var expected = ZeroTierAddress.Read(digest.AsSpan(59, 5));
            Assert.Equal(expected, address);
        }

        [Fact]
        public void DifferentKeys_ProduceDifferentDigests()
        {
            _derive.TryComputeDigest(PublicKey(1), out byte[] d1, out _);
            _derive.TryComputeDigest(PublicKey(2), out byte[] d2, out _);
            Assert.NotEqual(d1, d2);
        }

        [Fact]
        public void RejectsWrongPublicKeySize()
        {
            Assert.Throws<ArgumentException>(() => _derive.TryComputeDigest(new byte[63], out _, out _));
        }
    }
}
