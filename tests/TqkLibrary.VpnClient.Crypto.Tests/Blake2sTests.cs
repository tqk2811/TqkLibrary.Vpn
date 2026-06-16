using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class Blake2sTests
    {
        // Official BLAKE2s-256 (RFC 7693) reference digests for unkeyed input.
        [Theory]
        [InlineData("", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")]
        [InlineData("abc", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")]
        public void Blake2s_Unkeyed_MatchesReferenceVectors(string asciiInput, string expectedHex)
        {
            var hash = new Blake2s();
            Assert.Equal(32, hash.HashSizeInBytes);
            byte[] digest = new byte[hash.HashSizeInBytes];
            hash.ComputeHash(System.Text.Encoding.ASCII.GetBytes(asciiInput), digest);
            Assert.Equal(expectedHex, Convert.ToHexString(digest).ToLowerInvariant());
        }

        // Official keyed-BLAKE2s KAT (blake2s-kat.txt, first entry): empty input, 32-byte sequential key 00..1f.
        [Fact]
        public void Blake2sKeyedMac_EmptyInput_MatchesOfficialKat()
        {
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)i;

            byte[] mac = new byte[32];
            Blake2sKeyedMac.ComputeMac(key, ReadOnlySpan<byte>.Empty, mac);
            Assert.Equal("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
                Convert.ToHexString(mac).ToLowerInvariant());
        }

        [Fact]
        public void Blake2sKeyedMac_16ByteOutput_IsDeterministicAndKeySensitive()
        {
            // 16-byte output is the size WireGuard mac1/mac2 use.
            byte[] keyA = new byte[32];
            byte[] keyB = new byte[32];
            keyB[0] = 0x01;
            byte[] input = System.Text.Encoding.ASCII.GetBytes("wireguard mac1");

            byte[] a1 = new byte[16], a2 = new byte[16], b = new byte[16];
            Blake2sKeyedMac.ComputeMac(keyA, input, a1);
            Blake2sKeyedMac.ComputeMac(keyA, input, a2);
            Blake2sKeyedMac.ComputeMac(keyB, input, b);

            Assert.Equal(a1, a2);          // deterministic
            Assert.NotEqual(a1, b);        // sensitive to the key
        }

        [Fact]
        public void Blake2sKeyedMac_BadOutputLength_Throws()
        {
            byte[] key = new byte[32];
            Assert.Throws<ArgumentException>(() => Blake2sKeyedMac.ComputeMac(key, ReadOnlySpan<byte>.Empty, new byte[0]));
            Assert.Throws<ArgumentException>(() => Blake2sKeyedMac.ComputeMac(key, ReadOnlySpan<byte>.Empty, new byte[33]));
        }
    }
}
