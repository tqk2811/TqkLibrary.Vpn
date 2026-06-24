using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Nebula.Tests
{
    public class NebulaCertificateValidatorTests
    {
        readonly NebulaCertificateCodec _codec = new();
        readonly NebulaCertificateValidator _validator = new();
        readonly Ed25519Signer _ed = new();

        [Fact]
        public void VerifySignature_GenuineSignature_Accepts()
        {
            // Simulate a CA signing a host certificate exactly as Nebula does: sign Marshal(Details) with Ed25519.
            byte[] caSeed = new byte[32];
            for (int i = 0; i < 32; i++) caSeed[i] = (byte)(i + 3);
            byte[] caPub = _ed.DerivePublicKey(caSeed);

            var cert = new NebulaCertificate
            {
                Details = new NebulaCertificateDetails
                {
                    Name = "host",
                    Ips = { 0xC0A86405, 0xFFFFFF00 },
                    NotBefore = 1_700_000_000,
                    NotAfter = 1_800_000_000,
                    PublicKey = new Curve25519DhGroup().DerivePublicValue(new Curve25519DhGroup().GeneratePrivateKey()),
                },
            };
            byte[] signedDetails = _codec.MarshalDetails(cert.Details);
            cert.Signature = _ed.Sign(caSeed, signedDetails);

            // Re-marshal to wire then parse back, verifying against the recovered signed-details bytes.
            byte[] wire = _codec.MarshalCertificate(cert);
            var parsed = _codec.UnmarshalCertificate(wire, out byte[] recoveredDetails);

            Assert.True(_validator.VerifySignature(parsed, recoveredDetails, caPub));
        }

        [Fact]
        public void VerifySignature_WrongCaKey_Rejects()
        {
            byte[] caSeed = new byte[32];
            for (int i = 0; i < 32; i++) caSeed[i] = (byte)(i + 3);

            var details = new NebulaCertificateDetails { Name = "host", NotBefore = 1, NotAfter = 2 };
            byte[] signed = _codec.MarshalDetails(details);
            var cert = new NebulaCertificate { Details = details, Signature = _ed.Sign(caSeed, signed) };

            byte[] otherCaPub = _ed.DerivePublicKey(new byte[32]); // different key
            Assert.False(_validator.VerifySignature(cert, signed, otherCaPub));
        }

        [Fact]
        public void VerifySignature_TamperedDetails_Rejects()
        {
            byte[] caSeed = new byte[32];
            for (int i = 0; i < 32; i++) caSeed[i] = (byte)(i + 9);
            byte[] caPub = _ed.DerivePublicKey(caSeed);

            var details = new NebulaCertificateDetails { Name = "host", NotBefore = 1, NotAfter = 2 };
            byte[] signed = _codec.MarshalDetails(details);
            var cert = new NebulaCertificate { Details = details, Signature = _ed.Sign(caSeed, signed) };

            byte[] tampered = (byte[])signed.Clone();
            tampered[^1] ^= 0xFF;
            Assert.False(_validator.VerifySignature(cert, tampered, caPub));
        }

        [Fact]
        public void ComputeFingerprint_IsDeterministic_32Bytes()
        {
            var cert = new NebulaCertificate
            {
                Details = new NebulaCertificateDetails { Name = "ca", IsCa = true, NotBefore = 1, NotAfter = 2 },
                Signature = new byte[64],
            };
            byte[] fp1 = _validator.ComputeFingerprint(cert);
            byte[] fp2 = _validator.ComputeFingerprint(cert);
            Assert.Equal(32, fp1.Length);
            Assert.Equal(fp1, fp2);
        }
    }
}
