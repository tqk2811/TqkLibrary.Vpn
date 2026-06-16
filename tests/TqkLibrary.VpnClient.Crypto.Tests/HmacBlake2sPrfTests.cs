using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class HmacBlake2sPrfTests
    {
        const int Blake2sBlockSize = 64;

        [Fact]
        public void HmacBlake2s_OutputSize_Is32()
        {
            Assert.Equal(32, new HmacBlake2sPrf().OutputSizeInBytes);
        }

        // Cross-check against the textbook RFC 2104 two-pass HMAC built on the (separately KAT-verified) Blake2s
        // hash: HMAC(K,m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m)), with BLAKE2s's 64-byte block. Since Blake2s is
        // proven byte-correct in Blake2sTests, this transitively proves HmacBlake2sPrf is correct.
        [Theory]
        [InlineData("", "")]
        [InlineData("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265")] // "Hi There", RFC 4231-style inputs
        [InlineData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "57697265477561726420696e707574")]
        public void HmacBlake2s_MatchesTextbookHmacOverBlake2s(string keyHex, string msgHex)
        {
            byte[] key = Convert.FromHexString(keyHex);
            byte[] msg = Convert.FromHexString(msgHex);

            byte[] expected = TextbookHmacBlake2s(key, msg);

            byte[] actual = new byte[32];
            new HmacBlake2sPrf().Compute(key, msg, actual);

            Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(actual));
        }

        [Fact]
        public void HmacBlake2s_IsKeySensitive()
        {
            byte[] msg = System.Text.Encoding.ASCII.GetBytes("same message");
            byte[] k1 = new byte[16];
            byte[] k2 = new byte[16];
            k2[0] = 0x01;

            byte[] o1 = new byte[32], o2 = new byte[32];
            var prf = new HmacBlake2sPrf();
            prf.Compute(k1, msg, o1);
            prf.Compute(k2, msg, o2);
            Assert.NotEqual(o1, o2);
        }

        static byte[] TextbookHmacBlake2s(byte[] key, byte[] message)
        {
            var hash = new Blake2s();
            // Keys longer than the block size are hashed first (not exercised here, keys are <= 32).
            if (key.Length > Blake2sBlockSize)
            {
                byte[] hk = new byte[hash.HashSizeInBytes];
                hash.ComputeHash(key, hk);
                key = hk;
            }
            byte[] k = new byte[Blake2sBlockSize];
            Array.Copy(key, k, key.Length);

            byte[] inner = new byte[Blake2sBlockSize + message.Length];
            byte[] outer = new byte[Blake2sBlockSize + hash.HashSizeInBytes];
            for (int i = 0; i < Blake2sBlockSize; i++)
            {
                inner[i] = (byte)(k[i] ^ 0x36);
                outer[i] = (byte)(k[i] ^ 0x5c);
            }
            Array.Copy(message, 0, inner, Blake2sBlockSize, message.Length);

            byte[] innerHash = new byte[hash.HashSizeInBytes];
            hash.ComputeHash(inner, innerHash);
            Array.Copy(innerHash, 0, outer, Blake2sBlockSize, innerHash.Length);

            byte[] result = new byte[hash.HashSizeInBytes];
            hash.ComputeHash(outer, result);
            return result;
        }
    }
}
