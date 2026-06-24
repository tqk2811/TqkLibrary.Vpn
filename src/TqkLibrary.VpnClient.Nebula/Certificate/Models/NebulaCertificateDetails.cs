using TqkLibrary.VpnClient.Nebula.Certificate.Enums;

namespace TqkLibrary.VpnClient.Nebula.Certificate.Models
{
    /// <summary>
    /// The signed body of a Nebula certificate (<c>RawNebulaCertificateDetails</c>, cert_v1.proto). These are the
    /// bytes the CA signs: re-marshalling this in ascending field-number order must reproduce exactly the signed
    /// input. Field numbers: Name=1, Ips=2, Subnets=3, Groups=4, NotBefore=5, NotAfter=6, PublicKey=7, IsCA=8,
    /// Issuer=9, Curve=100.
    /// </summary>
    public sealed class NebulaCertificateDetails
    {
        /// <summary>Human-readable certificate name (field 1).</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Overlay addresses as interleaved (IPv4, netmask) uint32 pairs in network byte order (field 2, packed). For
        /// a host cert these are the addresses on the Nebula network; for a CA cert they bound which IPs it may sign.
        /// </summary>
        public List<uint> Ips { get; set; } = new();

        /// <summary>Unsafe-route subnets as interleaved (IPv4, netmask) uint32 pairs (field 3, packed).</summary>
        public List<uint> Subnets { get; set; } = new();

        /// <summary>Group memberships used by the Nebula firewall (field 4, repeated string).</summary>
        public List<string> Groups { get; set; } = new();

        /// <summary>Not-before validity time as a Unix timestamp in seconds (field 5).</summary>
        public long NotBefore { get; set; }

        /// <summary>Not-after validity time as a Unix timestamp in seconds (field 6).</summary>
        public long NotAfter { get; set; }

        /// <summary>
        /// The certificate's public key (field 7). For a host cert on Curve25519 this is the 32-byte X25519 key used
        /// as the Noise static DH key; for a CA cert it is the 32-byte Ed25519 verification key.
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>Whether this certificate is a certificate authority (field 8).</summary>
        public bool IsCa { get; set; }

        /// <summary>SHA-256 fingerprint of the issuing CA certificate (field 9); empty for a self-signed CA.</summary>
        public byte[] Issuer { get; set; } = Array.Empty<byte>();

        /// <summary>The curve the keys live on (field 100). Curve25519 (value 0) is omitted on the wire when default.</summary>
        public NebulaCurve Curve { get; set; } = NebulaCurve.Curve25519;
    }
}
