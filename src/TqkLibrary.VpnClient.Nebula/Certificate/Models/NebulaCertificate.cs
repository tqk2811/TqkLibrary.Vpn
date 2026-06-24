namespace TqkLibrary.VpnClient.Nebula.Certificate.Models
{
    /// <summary>
    /// A complete Nebula certificate (<c>RawNebulaCertificate</c>, cert_v1.proto): the signed
    /// <see cref="Details"/> (field 1) plus the CA's <see cref="Signature"/> over the marshaled details (field 2).
    /// </summary>
    public sealed class NebulaCertificate
    {
        /// <summary>The signed certificate body (field 1).</summary>
        public NebulaCertificateDetails Details { get; set; } = new();

        /// <summary>
        /// The CA signature over <c>Marshal(Details)</c> (field 2). 64-byte raw Ed25519 for Curve25519 certs, or
        /// ASN.1-DER ECDSA for P256 certs.
        /// </summary>
        public byte[] Signature { get; set; } = Array.Empty<byte>();
    }
}
