using System.Text;
using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    // n2n block-Pearson hash. Golden vectors are n2n's OWN tests-hashing expected output (512 bytes of 0x00..0x0f
    // repeated) plus values captured from libn2n.a for the "labnet" community — interop-critical for n2n -H.
    public class PearsonHashTests
    {
        // n2n tests-hashing input: 0,1,..,15 repeated 32 times = 512 bytes.
        static byte[] N2nHashTestInput()
        {
            byte[] b = new byte[512];
            for (int i = 0; i < 512; i++) b[i] = (byte)(i & 0x0f);
            return b;
        }

        [Fact]
        public void Pearson64_N2nHashingKat()
        {
            ulong h = PearsonHash.Hash64(N2nHashTestInput());
            Assert.Equal(0xb2d98fa82ea108beUL, h);
        }

        [Fact]
        public void Pearson128_N2nHashingKat()
        {
            byte[] o = PearsonHash.Hash128(N2nHashTestInput());
            Assert.Equal(Convert.FromHexString("b53dcfb3a7ed1856b2d98fa82ea108be"), o);
        }

        // Community "labnet" null-padded to N2N_COMMUNITY_SIZE (20) — the actual header-encryption key derivation input.
        static byte[] CommunityPadded(string community)
        {
            byte[] b = new byte[20];
            Encoding.ASCII.GetBytes(community).AsSpan().CopyTo(b);
            return b;
        }

        [Fact]
        public void Pearson64_Community_MatchesN2nGolden()
        {
            ulong h = PearsonHash.Hash64(CommunityPadded("labnet"));
            Assert.Equal(0xd65b0576726f51acUL, h);
        }

        [Fact]
        public void Pearson128_Community_MatchesN2nGolden()
        {
            byte[] o = PearsonHash.Hash128(CommunityPadded("labnet"));
            Assert.Equal(Convert.FromHexString("5a6967e48c605ef9d65b0576726f51ac"), o);
        }

        [Fact]
        public void Pearson128_HashOfHash_MatchesN2nGolden()
        {
            // n2n derives the IV key as pearson_hash_128 of the 16-byte community key.
            byte[] key = PearsonHash.Hash128(CommunityPadded("labnet"));
            byte[] ivKey = PearsonHash.Hash128(key);
            Assert.Equal(Convert.FromHexString("4138cafe430d1de322507281b09f0015"), ivKey);
        }

        [Fact]
        public void Pearson128_LowHalf_EqualsHash64()
        {
            byte[] data = Encoding.ASCII.GetBytes("the quick brown fox");
            byte[] h128 = PearsonHash.Hash128(data);
            ulong h64 = PearsonHash.Hash64(data);
            byte[] low = h128.AsSpan(8, 8).ToArray();
            Assert.Equal(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(low), h64);
        }
    }
}
