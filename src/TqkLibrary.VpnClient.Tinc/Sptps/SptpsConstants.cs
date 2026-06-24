namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>Wire-level constants for the modern (Ed25519/Curve25519) SPTPS cipher suite.</summary>
    public static class SptpsConstants
    {
        /// <summary>KEX version byte, <c>SPTPS_VERSION</c>.</summary>
        public const byte Version = 0;

        /// <summary>X25519 public-value / nonce size, <c>ECDH_SIZE</c>.</summary>
        public const int EcdhSize = 32;

        /// <summary>Nonce size in a KEX message (equals <see cref="EcdhSize"/> in tinc).</summary>
        public const int NonceSize = 32;

        /// <summary>Ed25519 signature size, <c>ECDSA_SIZE</c>.</summary>
        public const int SignatureSize = 64;

        /// <summary>One half of the derived <c>sptps_key_t</c> (a full cipher key), <c>CHACHA_POLY1305_KEYLEN</c>.</summary>
        public const int CipherKeySize = 64;

        /// <summary>Total derived key material, <c>sizeof(sptps_key_t)</c> = two cipher keys.</summary>
        public const int KeyMaterialSize = CipherKeySize * 2;

        /// <summary>The fixed KDF seed prefix (ASCII, no trailing NUL) prepended before the nonces and label.</summary>
        public const string KeyExpansionLabel = "key expansion";
    }
}
