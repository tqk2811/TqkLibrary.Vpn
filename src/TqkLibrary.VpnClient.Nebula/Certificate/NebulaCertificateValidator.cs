using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Nebula.Certificate.Enums;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;

namespace TqkLibrary.VpnClient.Nebula.Certificate
{
    /// <summary>
    /// Verifies Nebula certificates: that the CA's signature over the marshaled details is valid (Ed25519 on
    /// Curve25519 certs) and computes the SHA-256 fingerprint used as the <c>Issuer</c> reference. Only the
    /// Curve25519/Ed25519 path is implemented (the Nebula default); P256/ECDSA certs are reported unsupported.
    /// </summary>
    public sealed class NebulaCertificateValidator
    {
        readonly NebulaCertificateCodec _codec;
        readonly ISignatureAlgo _ed25519;
        readonly IHashAlgo _sha256;

        /// <summary>Creates a validator over the supplied codec/primitives (defaults to the Nebula set).</summary>
        public NebulaCertificateValidator(
            NebulaCertificateCodec? codec = null,
            ISignatureAlgo? ed25519 = null,
            IHashAlgo? sha256 = null)
        {
            _codec = codec ?? new NebulaCertificateCodec();
            _ed25519 = ed25519 ?? new Ed25519Signer();
            _sha256 = sha256 ?? new Sha256Hash();
        }

        /// <summary>
        /// Verifies <paramref name="certificate"/> against the issuing CA's <paramref name="caPublicKey"/> (the CA's
        /// 32-byte Ed25519 key). <paramref name="signedDetails"/> must be the exact marshaled details bytes from the
        /// certificate (as returned by <see cref="NebulaCertificateCodec.UnmarshalCertificate"/>). Returns false for
        /// a bad signature or an unsupported curve.
        /// </summary>
        public bool VerifySignature(NebulaCertificate certificate, ReadOnlySpan<byte> signedDetails, ReadOnlySpan<byte> caPublicKey)
        {
            if (certificate is null) throw new ArgumentNullException(nameof(certificate));
            if (certificate.Details.Curve != NebulaCurve.Curve25519) return false; // only Ed25519 path supported
            return _ed25519.Verify(caPublicKey, signedDetails, certificate.Signature);
        }

        /// <summary>
        /// Computes a certificate's SHA-256 fingerprint (over the full marshaled <see cref="NebulaCertificate"/>),
        /// the value used as the <c>Issuer</c> on certificates this CA signs.
        /// </summary>
        public byte[] ComputeFingerprint(NebulaCertificate certificate)
        {
            byte[] marshaled = _codec.MarshalCertificate(certificate);
            byte[] digest = new byte[_sha256.HashSizeInBytes];
            _sha256.ComputeHash(marshaled, digest);
            return digest;
        }
    }
}
