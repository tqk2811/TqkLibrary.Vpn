using System.Net;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Enums;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Tests
{
    /// <summary>
    /// Mints an in-process Nebula PKI for the offline tests: a CA (Ed25519 signing key) and host certificates signed by
    /// it, each with a 32-byte X25519 static key. This is the same shape <c>nebula-cert</c> produces (verified live in
    /// phase a) but generated entirely in-process — no external binary. Throwaway test scaffolding.
    /// </summary>
    sealed class NebulaTestPki
    {
        readonly NebulaCertificateCodec _codec = new();
        readonly Ed25519Signer _ed25519 = new();

        public byte[] CaEd25519Seed { get; }
        public byte[] CaPublicKey { get; }
        public NebulaCertificate CaCertificate { get; }

        public NebulaTestPki()
        {
            CaEd25519Seed = RandomSeed();
            CaPublicKey = _ed25519.DerivePublicKey(CaEd25519Seed);
            var caDetails = new NebulaCertificateDetails
            {
                Name = "Test CA",
                NotBefore = 1,
                NotAfter = 4102444800, // year 2100
                PublicKey = CaPublicKey,
                IsCa = true,
                Curve = NebulaCurve.Curve25519,
            };
            byte[] signed = _codec.MarshalDetails(caDetails);
            CaCertificate = new NebulaCertificate { Details = caDetails, Signature = _ed25519.Sign(CaEd25519Seed, signed) };
        }

        /// <summary>Signs a host certificate carrying <paramref name="overlay"/> and a fresh X25519 static key; returns the cert + the 32-byte X25519 private key.</summary>
        public (NebulaCertificate cert, byte[] x25519Private) SignHost(string name, IPAddress overlay, int prefix)
        {
            var dh = new Curve25519DhGroup();
            byte[] x25519Private = dh.GeneratePrivateKey();
            byte[] x25519Public = dh.DerivePublicValue(x25519Private);

            var details = new NebulaCertificateDetails
            {
                Name = name,
                NotBefore = 1,
                NotAfter = 4102444800,
                PublicKey = x25519Public,
                Curve = NebulaCurve.Curve25519,
            };
            details.Ips.Add(ToIpUint(overlay));
            details.Ips.Add(PrefixToMask(prefix));

            byte[] signed = _codec.MarshalDetails(details);
            var cert = new NebulaCertificate { Details = details, Signature = _ed25519.Sign(CaEd25519Seed, signed) };
            return (cert, x25519Private);
        }

        static uint ToIpUint(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        static uint PrefixToMask(int prefix) => prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);

        static byte[] RandomSeed()
        {
            byte[] s = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(s); // distinct CA per instance (a rogue CA must differ)
            return s;
        }
    }
}
