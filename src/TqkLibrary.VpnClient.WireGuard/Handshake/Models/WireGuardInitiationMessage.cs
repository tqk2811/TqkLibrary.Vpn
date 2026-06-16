namespace TqkLibrary.VpnClient.WireGuard.Handshake.Models
{
    /// <summary>
    /// A decoded WireGuard handshake-<b>initiation</b> message (type 1, whitepaper §5.4.2). Wire layout (148 bytes):
    /// <c>type(1) | reserved(3) | sender(4) | ephemeral(32) | encrypted_static(32+16) | encrypted_timestamp(12+16)
    /// | mac1(16) | mac2(16)</c>. This holds the on-wire fields verbatim — decryption/verification is the
    /// <see cref="WireGuardHandshake"/>'s job; mac1/mac2 are populated/checked by the V3.c machinery.
    /// </summary>
    public sealed record WireGuardInitiationMessage
    {
        /// <summary>The initiator's locally-chosen session index (little-endian on the wire).</summary>
        public required uint SenderIndex { get; init; }

        /// <summary>The initiator's ephemeral X25519 public key (32 bytes, sent in the clear).</summary>
        public required byte[] UnencryptedEphemeral { get; init; }

        /// <summary>The initiator's static public key, AEAD-sealed (32 ciphertext + 16 tag = 48 bytes).</summary>
        public required byte[] EncryptedStatic { get; init; }

        /// <summary>The TAI64N timestamp, AEAD-sealed (12 ciphertext + 16 tag = 28 bytes).</summary>
        public required byte[] EncryptedTimestamp { get; init; }

        /// <summary>mac1 (keyed BLAKE2s, 16 bytes). Computed/verified in V3.c; zero before that.</summary>
        public byte[] Mac1 { get; init; } = new byte[WireGuardConstants.MacLength];

        /// <summary>mac2 (cookie MAC, 16 bytes). Computed/verified in V3.c; zero when no cookie is in use.</summary>
        public byte[] Mac2 { get; init; } = new byte[WireGuardConstants.MacLength];
    }
}
