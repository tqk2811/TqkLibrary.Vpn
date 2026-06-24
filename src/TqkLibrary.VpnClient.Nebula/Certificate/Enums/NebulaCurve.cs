namespace TqkLibrary.VpnClient.Nebula.Certificate.Enums
{
    /// <summary>
    /// The elliptic curve a Nebula certificate's keys live on (cert.proto <c>Curve</c> enum). Determines both the DH
    /// curve for the Noise handshake and the CA's signature scheme.
    /// </summary>
    public enum NebulaCurve
    {
        /// <summary>Curve25519: X25519 DH public key, Ed25519 CA signatures. The Nebula default (proto value 0).</summary>
        Curve25519 = 0,

        /// <summary>NIST P-256: ECDH P-256 DH, ECDSA-P256/SHA-256 CA signatures (proto value 1).</summary>
        P256 = 1,
    }
}
