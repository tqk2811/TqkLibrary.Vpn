using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Enums;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Nebula.Tests
{
    public class NebulaCertificateCodecTests
    {
        readonly NebulaCertificateCodec _codec = new();

        static NebulaCertificateDetails SampleDetails() => new()
        {
            Name = "client",
            Ips = { 0xC0A86419, 0xFFFFFF00 },        // 192.168.100.25 / 255.255.255.0
            Groups = { "users", "laptop" },
            NotBefore = 1_700_000_000,
            NotAfter = 1_800_000_000,
            PublicKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
            IsCa = false,
            Issuer = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray(),
            Curve = NebulaCurve.Curve25519,
        };

        [Fact]
        public void Details_RoundTrip()
        {
            var d = SampleDetails();
            byte[] bytes = _codec.MarshalDetails(d);
            var back = _codec.UnmarshalDetails(bytes);

            Assert.Equal(d.Name, back.Name);
            Assert.Equal(d.Ips, back.Ips);
            Assert.Equal(d.Groups, back.Groups);
            Assert.Equal(d.NotBefore, back.NotBefore);
            Assert.Equal(d.NotAfter, back.NotAfter);
            Assert.Equal(d.PublicKey, back.PublicKey);
            Assert.Equal(d.IsCa, back.IsCa);
            Assert.Equal(d.Issuer, back.Issuer);
            Assert.Equal(d.Curve, back.Curve);
        }

        [Fact]
        public void MarshalDetails_OmitsProto3Defaults()
        {
            // An all-default details object should marshal to zero bytes (proto3 omits defaults).
            var empty = new NebulaCertificateDetails();
            Assert.Empty(_codec.MarshalDetails(empty));

            // Curve25519 (default 0) must not appear; P256 must.
            var p256 = new NebulaCertificateDetails { Name = "x", Curve = NebulaCurve.P256 };
            byte[] withP256 = _codec.MarshalDetails(p256);
            // field 100, wire type 0 => tag = 100<<3 = 800 = 0xA0 0x06 varint
            Assert.Contains(withP256, _ => true);
            Assert.True(ContainsSequence(withP256, new byte[] { 0xA0, 0x06, 0x01 })); // tag(100,varint)+value 1
        }

        [Fact]
        public void MarshalDetails_IsDeterministic_AscendingFieldOrder()
        {
            var d = SampleDetails();
            byte[] a = _codec.MarshalDetails(d);
            byte[] b = _codec.MarshalDetails(d);
            Assert.Equal(a, b);
            // Name (field 1, tag 0x0A) must be the first byte.
            Assert.Equal(0x0A, a[0]);
        }

        [Fact]
        public void Certificate_RoundTrip_PreservesSignedDetailsBytes()
        {
            var cert = new NebulaCertificate
            {
                Details = SampleDetails(),
                Signature = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray(),
            };
            byte[] expectedSignedDetails = _codec.MarshalDetails(cert.Details);

            byte[] marshaled = _codec.MarshalCertificate(cert);
            var back = _codec.UnmarshalCertificate(marshaled, out byte[] signedDetails);

            Assert.Equal(cert.Signature, back.Signature);
            Assert.Equal(cert.Details.Name, back.Details.Name);
            // The raw signed-details bytes recovered on parse must equal a fresh marshal (verification depends on this).
            Assert.Equal(expectedSignedDetails, signedDetails);
        }

        [Fact]
        public void PackedUInt32_Empty_NotWritten()
        {
            var d = new NebulaCertificateDetails { Name = "n" };
            byte[] bytes = _codec.MarshalDetails(d);
            var back = _codec.UnmarshalDetails(bytes);
            Assert.Empty(back.Ips);
            Assert.Empty(back.Subnets);
        }

        static bool ContainsSequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { ok = false; break; }
                if (ok) return true;
            }
            return false;
        }
    }
}
