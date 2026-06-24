using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>KEX wire codec and PRF determinism/length.</summary>
    public class SptpsCodecTests
    {
        [Fact]
        public void Kex_RoundTrips_65Bytes()
        {
            byte[] nonce = new byte[32];
            byte[] pub = new byte[32];
            for (int i = 0; i < 32; i++) { nonce[i] = (byte)i; pub[i] = (byte)(255 - i); }
            var kex = new SptpsKex(SptpsConstants.Version, nonce, pub);

            byte[] wire = kex.ToBytes();
            Assert.Equal(SptpsKex.Size, wire.Length);
            Assert.Equal(65, wire.Length);
            Assert.Equal(0, wire[0]);

            var parsed = SptpsKex.Parse(wire);
            Assert.Equal(nonce, parsed.Nonce);
            Assert.Equal(pub, parsed.PublicKey);
        }

        [Fact]
        public void Prf_IsDeterministic_AndCorrectLength()
        {
            byte[] secret = System.Text.Encoding.ASCII.GetBytes("shared-secret-32-bytes-padding!!");
            byte[] seed = System.Text.Encoding.ASCII.GetBytes("key expansion-seed");

            byte[] a = SptpsPrf.Expand(secret, seed, 128);
            byte[] b = SptpsPrf.Expand(secret, seed, 128);

            Assert.Equal(128, a.Length);
            Assert.Equal(a, b);
            // Different seed → different output.
            byte[] c = SptpsPrf.Expand(secret, System.Text.Encoding.ASCII.GetBytes("other-seed"), 128);
            Assert.NotEqual(a, c);
        }

        [Fact]
        public void Prf_FirstHalfPrefixesLongerExpansion()
        {
            // P_hash blocks chain, so the first 64 bytes of a 128-byte expansion equal a 64-byte expansion.
            byte[] secret = { 1, 2, 3, 4 };
            byte[] seed = { 9, 9, 9 };
            byte[] short64 = SptpsPrf.Expand(secret, seed, 64);
            byte[] long128 = SptpsPrf.Expand(secret, seed, 128);
            Assert.Equal(short64, long128.AsSpan(0, 64).ToArray());
        }

        [Fact]
        public void MetaLabel_HasTrailingNul()
        {
            byte[] label = SptpsHandshake.BuildMetaLabel("a", "b");
            // "tinc TCP key expansion a b" = 26 chars + NUL = 27.
            Assert.Equal(27, label.Length);
            Assert.Equal(0, label[label.Length - 1]);
        }
    }
}
