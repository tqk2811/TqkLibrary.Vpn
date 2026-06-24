using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    public class Vl1KeyAndHelloTests
    {
        [Fact]
        public void DeriveSharedKey_IsSymmetricBetweenPeers()
        {
            var dh = new Curve25519DhGroup();
            byte[] aPriv = dh.GeneratePrivateKey();
            byte[] aPub = dh.DerivePublicValue(aPriv);
            byte[] bPriv = dh.GeneratePrivateKey();
            byte[] bPub = dh.DerivePublicValue(bPriv);

            var kdf = new Vl1KeyDerivation();
            byte[] keyAtoB = kdf.DeriveSharedKey(aPriv, bPub);
            byte[] keyBtoA = kdf.DeriveSharedKey(bPriv, aPub);

            Assert.Equal(Vl1KeyDerivation.KeySize, keyAtoB.Length);
            Assert.Equal(keyAtoB, keyBtoA); // both ends derive the identical secret
        }

        [Fact]
        public void DeriveSharedKey_DiffersForDifferentPeers()
        {
            var dh = new Curve25519DhGroup();
            byte[] aPriv = dh.GeneratePrivateKey();
            byte[] bPub = dh.DerivePublicValue(dh.GeneratePrivateKey());
            byte[] cPub = dh.DerivePublicValue(dh.GeneratePrivateKey());

            var kdf = new Vl1KeyDerivation();
            Assert.NotEqual(kdf.DeriveSharedKey(aPriv, bPub), kdf.DeriveSharedKey(aPriv, cPub));
        }

        [Fact]
        public void HelloMessage_RoundTrips()
        {
            byte[] pub = new byte[ZeroTierIdentity.PublicKeySize];
            for (int i = 0; i < pub.Length; i++) pub[i] = (byte)(i + 11);

            var hello = new HelloMessage
            {
                ProtocolVersion = 12,
                VersionMajor = 1,
                VersionMinor = 14,
                VersionRevision = 2,
                Timestamp = 1_700_000_000_000UL,
                Identity = new ZeroTierIdentity
                {
                    Address = ZeroTierAddress.Parse("8056c2e21c"),
                    PublicKey = pub,
                },
            };

            var codec = new HelloMessageCodec();
            byte[] body = codec.Encode(hello);
            Assert.True(codec.TryDecode(body, out var parsed));

            Assert.Equal(hello.ProtocolVersion, parsed.ProtocolVersion);
            Assert.Equal(hello.VersionMajor, parsed.VersionMajor);
            Assert.Equal(hello.VersionMinor, parsed.VersionMinor);
            Assert.Equal(hello.VersionRevision, parsed.VersionRevision);
            Assert.Equal(hello.Timestamp, parsed.Timestamp);
            Assert.Equal(hello.Identity.Address, parsed.Identity.Address);
            Assert.Equal(hello.Identity.PublicKey, parsed.Identity.PublicKey);
        }

        [Fact]
        public void HelloMessage_TryDecode_RejectsShortBody()
        {
            var codec = new HelloMessageCodec();
            Assert.False(codec.TryDecode(new byte[10], out _));
        }
    }
}
