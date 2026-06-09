namespace TqkLibrary.Vpn.Ipsec.Esp.Enums
{
    /// <summary>The ESP confidentiality transform a CHILD/Phase-2 SA was negotiated with.</summary>
    public enum EspEncryptionAlgorithm
    {
        /// <summary>AES-CBC with a separate HMAC integrity algorithm (encrypt-then-MAC).</summary>
        AesCbc,

        /// <summary>AES-GCM AEAD with a 16-octet ICV (RFC 4106): one key, 4-byte salt, no separate integrity.</summary>
        AesGcm16,
    }
}
