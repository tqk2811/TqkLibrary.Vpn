using TqkLibrary.VpnClient.Crypto;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class Salsa20Tests
    {
        // ECRYPT eSTREAM Salsa20 known-answer keystreams (256-bit key, 64-bit IV), stream bytes [0..63].
        //   * all-zero key/IV  — the standard "Set 1" baseline.
        //   * key = 80 00...00 — ECRYPT verified Set 1, vector 0.
        // Salsa20/12 uses the same inputs with 12 rounds. These pin the engine byte-exact, independent of any lab.
        [Theory]
        // all-zero key/IV, Salsa20/20
        [InlineData(20,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000",
            "9A97F65B9B4C721B960A672145FCA8D4E32E67F9111EA979CE9C4826806AEEE63DE9C0DA2BD7F91EBCB2639BF989C6251B29BF38D39A9BDCE7C55F4B2AC12A39")]
        // all-zero key/IV, Salsa20/12
        [InlineData(12,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000",
            "BD78A2F8118A563C761DB4F2FBE055DA97F90988D27594D9C5DFD13A3EFEAA3F68F0D2564850ADF5017433968E4B3405AC49A39532124FCD6F47E415C7028A83")]
        // ECRYPT Set 1 vector 0 (key MSB set), Salsa20/20
        [InlineData(20,
            "8000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000",
            "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117")]
        // ECRYPT Set 1 vector 0 (key MSB set), Salsa20/12 — ZeroTier VL1 packet round count
        [InlineData(12,
            "8000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000",
            "AFE411ED1C4E07E4D0CDE3B33E31EC190FA4CC796A58BAFB848EAD8D07D02CD2D4B6F9F30CB0B57007E3733895CC8D1060107975ACAEEB689B6CF614AB64A3D6")]
        public void Salsa20_KeystreamMatchesEcryptVectors(int rounds, string keyHex, string ivHex, string expectedHex)
        {
            var salsa = new Salsa20(rounds);
            Assert.Equal(rounds, salsa.Rounds);
            byte[] key = Convert.FromHexString(keyHex);
            byte[] iv = Convert.FromHexString(ivHex);

            byte[] keystream = new byte[expectedHex.Length / 2];
            salsa.GenerateKeystream(key, iv, keystream);
            Assert.Equal(expectedHex, Convert.ToHexString(keystream));

            // Transform of zeros equals the raw keystream.
            byte[] viaTransform = new byte[keystream.Length];
            salsa.Transform(key, iv, new byte[keystream.Length], viaTransform);
            Assert.Equal(keystream, viaTransform);
        }

        [Fact]
        public void Salsa20_EncryptThenDecrypt_RoundTrips()
        {
            var salsa = new Salsa20(12);
            byte[] key = new byte[Salsa20.KeyBytes];
            byte[] iv = new byte[Salsa20.NonceBytes];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(i * 3 + 1);
            for (int i = 0; i < iv.Length; i++) iv[i] = (byte)(0xA0 + i);

            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("ZeroTier VL1 payload — Salsa20/12 stream cipher.");
            byte[] ciphertext = new byte[plaintext.Length];
            salsa.Transform(key, iv, plaintext, ciphertext);
            Assert.NotEqual(plaintext, ciphertext);

            byte[] recovered = new byte[plaintext.Length];
            salsa.Transform(key, iv, ciphertext, recovered);
            Assert.Equal(plaintext, recovered);
        }

        [Fact]
        public void Salsa20_RejectsBadParameters()
        {
            Assert.Throws<ArgumentException>(() => new Salsa20(13));   // odd rounds
            Assert.Throws<ArgumentException>(() => new Salsa20(0));    // zero rounds
            var salsa = new Salsa20();
            Assert.Equal(20, salsa.Rounds);                            // default = Salsa20/20
            Assert.Throws<ArgumentException>(() => salsa.Transform(new byte[31], new byte[8], new byte[1], new byte[1]));
            Assert.Throws<ArgumentException>(() => salsa.Transform(new byte[32], new byte[7], new byte[1], new byte[1]));
        }
    }
}
