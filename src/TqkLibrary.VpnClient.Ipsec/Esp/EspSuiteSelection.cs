using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Ipsec.Esp.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// Describes the ESP cipher suite negotiated for a CHILD/Phase-2 SA and turns one direction's keying material
    /// into the matching <see cref="EspCipherSuite"/>. It is the single place that maps an algorithm choice to its
    /// key-material layout, so IKEv1 Quick Mode and IKEv2 CHILD_SA derivation share the same lengths and builders.
    ///
    /// Keying material per direction is laid out as <c>encryption-key ‖ second-slice</c>: for AES-CBC the second
    /// slice is the integrity (HMAC) key; for AES-GCM it is the 4-byte salt (RFC 4106 §8.1).
    /// </summary>
    public sealed class EspSuiteSelection
    {
        const int GcmSaltLength = 4;

        readonly Func<IIntegrityAlgo>? _integrityFactory; // AES-CBC only; null for AEAD

        EspSuiteSelection(EspEncryptionAlgorithm algorithm, int encryptionKeyLengthBytes, int secondSliceLengthBytes,
            Func<IIntegrityAlgo>? integrityFactory)
        {
            if (encryptionKeyLengthBytes != 16 && encryptionKeyLengthBytes != 24 && encryptionKeyLengthBytes != 32)
                throw new ArgumentException("ESP AES key must be 16, 24 or 32 bytes.", nameof(encryptionKeyLengthBytes));
            Algorithm = algorithm;
            EncryptionKeyLengthBytes = encryptionKeyLengthBytes;
            SecondSliceLengthBytes = secondSliceLengthBytes;
            _integrityFactory = integrityFactory;
        }

        /// <summary>The negotiated confidentiality transform.</summary>
        public EspEncryptionAlgorithm Algorithm { get; }

        /// <summary>The AES key length in bytes (16/24/32).</summary>
        public int EncryptionKeyLengthBytes { get; }

        /// <summary>Length of the second key-material slice per direction: the integrity key (CBC) or the salt (GCM).</summary>
        public int SecondSliceLengthBytes { get; }

        /// <summary>Total keying material consumed per direction (encryption key + second slice).</summary>
        public int KeyMaterialLengthPerDirection => EncryptionKeyLengthBytes + SecondSliceLengthBytes;

        /// <summary>AES-CBC + HMAC-SHA-1-96 (the common IKEv1 ESP SA): integrity key 20 bytes.</summary>
        public static EspSuiteSelection AesCbcHmacSha1(int encryptionKeyLengthBytes = 32)
            => new(EspEncryptionAlgorithm.AesCbc, encryptionKeyLengthBytes, 20, () => HmacIntegrity.HmacSha1_96());

        /// <summary>AES-CBC + HMAC-SHA-256-128 (the default IKEv2 ESP SA): integrity key 32 bytes.</summary>
        public static EspSuiteSelection AesCbcHmacSha256(int encryptionKeyLengthBytes = 32)
            => new(EspEncryptionAlgorithm.AesCbc, encryptionKeyLengthBytes, 32, () => HmacIntegrity.HmacSha256_128());

        /// <summary>AES-GCM with a 16-octet ICV (RFC 4106): 4-byte salt, no separate integrity key.</summary>
        public static EspSuiteSelection AesGcm16(int encryptionKeyLengthBytes = 32)
            => new(EspEncryptionAlgorithm.AesGcm16, encryptionKeyLengthBytes, GcmSaltLength, null);

        /// <summary>
        /// Builds the directional <see cref="EspCipherSuite"/> from one direction's key material:
        /// <paramref name="encryptionKey"/> (length <see cref="EncryptionKeyLengthBytes"/>) followed by
        /// <paramref name="secondSlice"/> (length <see cref="SecondSliceLengthBytes"/> — integrity key or salt).
        /// </summary>
        public EspCipherSuite BuildSuite(byte[] encryptionKey, byte[] secondSlice)
            => Algorithm == EspEncryptionAlgorithm.AesGcm16
                ? EspCipherSuite.AesGcm(encryptionKey, secondSlice)
                : new EspCbcHmacSuite(encryptionKey, secondSlice, _integrityFactory!());
    }
}
