using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class Curve25519DhGroupTests
    {
        // RFC 7748 §5.2 — single X25519 scalar-mult test vectors: X25519(scalar, u) == output.
        [Theory]
        [InlineData(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
        [InlineData(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
        public void X25519_ScalarMult_MatchesRfc7748(string scalarHex, string uHex, string expectedHex)
        {
            var dh = new Curve25519DhGroup();
            byte[] secret = dh.DeriveSharedSecret(Convert.FromHexString(scalarHex), Convert.FromHexString(uHex));
            Assert.Equal(expectedHex, Convert.ToHexString(secret).ToLowerInvariant());
        }

        // RFC 7748 §6.1 — full Diffie-Hellman exchange (Alice + Bob known keys -> known shared secret K).
        [Fact]
        public void X25519_DiffieHellman_MatchesRfc7748Section6()
        {
            var dh = new Curve25519DhGroup();
            byte[] alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] bobPriv = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            const string alicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
            const string bobPub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
            const string sharedK = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

            Assert.Equal(alicePub, Convert.ToHexString(dh.DerivePublicValue(alicePriv)).ToLowerInvariant());
            Assert.Equal(bobPub, Convert.ToHexString(dh.DerivePublicValue(bobPriv)).ToLowerInvariant());
            Assert.Equal(sharedK, Convert.ToHexString(dh.DeriveSharedSecret(alicePriv, Convert.FromHexString(bobPub))).ToLowerInvariant());
            Assert.Equal(sharedK, Convert.ToHexString(dh.DeriveSharedSecret(bobPriv, Convert.FromHexString(alicePub))).ToLowerInvariant());
        }

        [Fact]
        public void X25519_GeneratedKeyPair_BothPartiesAgree()
        {
            var dh = new Curve25519DhGroup();
            Assert.Equal(31, dh.GroupId);
            Assert.Equal(32, dh.PublicValueSizeInBytes);

            byte[] aPriv = dh.GeneratePrivateKey();
            byte[] aPub = dh.DerivePublicValue(aPriv);
            byte[] bPriv = dh.GeneratePrivateKey();
            byte[] bPub = dh.DerivePublicValue(bPriv);

            Assert.Equal(32, aPriv.Length);
            Assert.Equal(32, aPub.Length);

            byte[] aShared = dh.DeriveSharedSecret(aPriv, bPub);
            byte[] bShared = dh.DeriveSharedSecret(bPriv, aPub);
            Assert.Equal(aShared, bShared);
            Assert.Contains(aShared, x => x != 0);
        }

        [Fact]
        public void X25519_WrongLength_Throws()
        {
            var dh = new Curve25519DhGroup();
            Assert.Throws<ArgumentException>(() => dh.DerivePublicValue(new byte[31]));
            Assert.Throws<ArgumentException>(() => dh.DeriveSharedSecret(new byte[32], new byte[16]));
        }
    }
}
