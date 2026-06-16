using System.Security.Cryptography;
using System.Text;
using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    /// <summary>
    /// Known-answer tests for SHA-0 (FIPS 180, 1993). SHA-0 is SHA-1 with the single-bit left-rotate
    /// removed from the message schedule, so its digests differ from SHA-1 for every non-empty padding.
    /// Used by SoftEther SSL-VPN password authentication (V.4).
    /// </summary>
    public class Sha0Tests
    {
        // FIPS 180 SHA-0 reference digests (the canonical "abc" + the 56-byte two-block example),
        // plus the empty-string digest.
        [Theory]
        [InlineData("", "f96cea198ad1dd5617ac084a3d92c6107708c0ef")]
        [InlineData("abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")]
        [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8")]
        public void Sha0_MatchesFips180(string message, string expectedHex)
        {
            byte[] hash = Sha0.Hash(Encoding.ASCII.GetBytes(message));
            Assert.Equal(expectedHex, Convert.ToHexString(hash).ToLowerInvariant());
        }

        [Fact]
        public void Sha0_HashSizeIs20Bytes()
        {
            Assert.Equal(20, new Sha0().HashSizeInBytes);
            Assert.Equal(20, Sha0.Hash(Array.Empty<byte>()).Length);
        }

        [Fact]
        public void Sha0_DiffersFromSha1_ForAbc()
        {
            byte[] input = Encoding.ASCII.GetBytes("abc");
            byte[] sha0 = Sha0.Hash(input);
            byte[] sha1 = SHA1.HashData(input);

            // SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d (FIPS 180-1) — must NOT equal SHA-0.
            Assert.Equal("a9993e364706816aba3e25717850c26c9cd0d89d", Convert.ToHexString(sha1).ToLowerInvariant());
            Assert.NotEqual(sha1, sha0);
        }

        [Fact]
        public void Sha0_DiffersFromSha1_ForEmptyAndLong()
        {
            foreach (string message in new[] { "", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "The quick brown fox jumps over the lazy dog" })
            {
                byte[] input = Encoding.ASCII.GetBytes(message);
                Assert.NotEqual(SHA1.HashData(input), Sha0.Hash(input));
            }
        }

        [Fact]
        public void Sha0_ComputeHash_RejectsShortDestination()
        {
            var sha0 = new Sha0();
            byte[] tooSmall = new byte[19];
            Assert.Throws<ArgumentException>(() => sha0.ComputeHash(Encoding.ASCII.GetBytes("abc"), tooSmall));
        }

        [Fact]
        public void Sha0_HandlesMultiBlockInput()
        {
            // 1000-byte input spans many 64-byte blocks; result is deterministic and 20 bytes.
            byte[] input = new byte[1000];
            for (int i = 0; i < input.Length; i++) input[i] = (byte)(i & 0xff);

            byte[] a = Sha0.Hash(input);
            byte[] b = Sha0.Hash(input);
            Assert.Equal(a, b);
            Assert.Equal(20, a.Length);
            Assert.NotEqual(SHA1.HashData(input), a);
        }
    }
}
