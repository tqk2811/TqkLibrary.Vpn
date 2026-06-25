using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    // SPECK 128/128 as used by n2n header-encryption. Golden vectors captured from the real n2n v3.1.1 reference
    // (libn2n.a) so the byte/word order matches byte-exact — this is interop-critical for n2n -H.
    public class SpeckTests
    {
        // Key = pearson_hash_128("labnet" padded to 20) = 5a6967e48c605ef9d65b0576726f51ac (the n2n header key).
        const string CommunityKeyHex = "5a6967e48c605ef9d65b0576726f51ac";

        [Fact]
        public void Speck_EncryptsZeroBlock_MatchesN2nGolden()
        {
            byte[] key = Convert.FromHexString(CommunityKeyHex);
            byte[] block = new byte[16]; // all zero
            var speck = new Speck(key);
            speck.EncryptBlock(block);
            Assert.Equal(Convert.FromHexString("204a0e00a0282d6e89e77f1292b7c82c"), block);
        }

        [Fact]
        public void Speck_EncryptsIncrementingBlock_MatchesN2nGolden()
        {
            byte[] key = Convert.FromHexString(CommunityKeyHex);
            byte[] block = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
            var speck = new Speck(key);
            speck.EncryptBlock(block);
            Assert.Equal(Convert.FromHexString("b20b5f45eed374cd00630545d9ab194f"), block);
        }

        [Fact]
        public void Speck_BlockRoundTrips()
        {
            byte[] key = Convert.FromHexString(CommunityKeyHex);
            byte[] original = Convert.FromHexString("00112233445566778899aabbccddeeff");
            byte[] block = (byte[])original.Clone();
            var speck = new Speck(key);
            speck.EncryptBlock(block);
            Assert.NotEqual(original, block);
            speck.DecryptBlock(block);
            Assert.Equal(original, block);
        }

        // NSA Speck128/128 test-vector key/plaintext, loaded the way n2n loads it (little-endian words). The output
        // therefore differs from the published big-number form, but matches the n2n reference for the same bytes.
        [Fact]
        public void Speck_NsaVectorBytes_MatchesN2nGolden()
        {
            byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
            byte[] block = Convert.FromHexString("6c61766975716520746920656461 6d20".Replace(" ", ""));
            var speck = new Speck(key);
            speck.EncryptBlock(block);
            Assert.Equal(Convert.FromHexString("3ba712cf696513c842edb68fbdd72f58"), block);
        }

        [Fact]
        public void Speck_Ctr_IsSymmetricAndNonIdentity()
        {
            byte[] key = Convert.FromHexString(CommunityKeyHex);
            byte[] iv = Convert.FromHexString("0102030405060708090a0b0c0d0e0f10");
            byte[] plain = Convert.FromHexString("11121314151617181920"); // 10 bytes (< one block, exercises partial path)
            var speck = new Speck(key);

            byte[] ct = new byte[plain.Length];
            speck.Ctr(iv, plain, ct);
            Assert.NotEqual(plain, ct);

            byte[] back = new byte[plain.Length];
            speck.Ctr(iv, ct, back);
            Assert.Equal(plain, back);
        }
    }
}
