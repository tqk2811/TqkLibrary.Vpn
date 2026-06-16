using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class NoiseKdfTests
    {
        static readonly IPrf Prf = new HmacBlake2sPrf();
        static readonly byte[] Key = System.Text.Encoding.ASCII.GetBytes("chain-key-or-construction-hash..");   // 32 bytes
        static readonly byte[] Input = System.Text.Encoding.ASCII.GetBytes("dh-result-or-public-key");

        // The HKDF chain shares the same extract step t0, so KDF1/KDF2/KDF3 agree on their common prefix blocks:
        // T1 = HMAC(t0, 0x01) is identical across all three, T2 across KDF2/KDF3, etc.
        [Fact]
        public void NoiseKdf_OutputsArePrefixConsistentAcrossKdf1Kdf2Kdf3()
        {
            byte[] k1 = NoiseKdf.Kdf1(Prf, Key, Input);
            (byte[] t1, byte[] t2) = NoiseKdf.Kdf2(Prf, Key, Input);
            (byte[] u1, byte[] u2, byte[] u3) = NoiseKdf.Kdf3(Prf, Key, Input);

            Assert.Equal(32, k1.Length);
            Assert.Equal(k1, t1);   // KDF1 == first block of KDF2
            Assert.Equal(t1, u1);   // == first block of KDF3
            Assert.Equal(t2, u2);   // second block matches between KDF2 and KDF3

            // Distinct blocks (the chain must not repeat).
            Assert.NotEqual(u1, u2);
            Assert.NotEqual(u2, u3);
            Assert.NotEqual(u1, u3);
        }

        [Fact]
        public void NoiseKdf_IsDeterministicAndInputSensitive()
        {
            (byte[] a1, byte[] a2) = NoiseKdf.Kdf2(Prf, Key, Input);
            (byte[] b1, byte[] b2) = NoiseKdf.Kdf2(Prf, Key, Input);
            Assert.Equal(a1, b1);
            Assert.Equal(a2, b2);

            byte[] otherInput = (byte[])Input.Clone();
            otherInput[0] ^= 0x01;
            (byte[] c1, _) = NoiseKdf.Kdf2(Prf, Key, otherInput);
            Assert.NotEqual(a1, c1);
        }

        // T1 = HMAC(t0, 0x01) where t0 = HMAC(key, input): verify the documented extract-then-expand structure.
        [Fact]
        public void NoiseKdf_Kdf1_EqualsExpandOfExtract()
        {
            byte[] t0 = new byte[32];
            Prf.Compute(Key, Input, t0);

            byte[] expectedT1 = new byte[32];
            Prf.Compute(t0, new byte[] { 0x01 }, expectedT1);

            byte[] kdf1 = NoiseKdf.Kdf1(Prf, Key, Input);
            Assert.Equal(expectedT1, kdf1);
        }

        [Fact]
        public void NoiseKdf_RejectsPrfWithWrongOutputSize()
        {
            // The KDF requires a 32-byte PRF (HMAC-BLAKE2s). A 20-byte PRF (HMAC-SHA1) must be rejected,
            // and outputs out of [1,255] too.
            var sha1Prf = new HmacPrf(System.Security.Cryptography.HashAlgorithmName.SHA1); // 20-byte output
            Assert.Throws<ArgumentException>(() => NoiseKdf.Derive(sha1Prf, Key, Input, 2));
            Assert.Throws<ArgumentOutOfRangeException>(() => NoiseKdf.Derive(Prf, Key, Input, 0));
        }
    }
}
