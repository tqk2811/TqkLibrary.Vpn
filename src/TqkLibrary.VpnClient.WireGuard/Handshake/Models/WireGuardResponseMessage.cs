namespace TqkLibrary.VpnClient.WireGuard.Handshake.Models
{
    /// <summary>
    /// A decoded WireGuard handshake-<b>response</b> message (type 2, whitepaper §5.4.3). Wire layout (92 bytes):
    /// <c>type(1) | reserved(3) | sender(4) | receiver(4) | ephemeral(32) | encrypted_nothing(0+16) | mac1(16)
    /// | mac2(16)</c>. <c>encrypted_nothing</c> is an empty AEAD payload — a 16-byte tag binding the transcript.
    /// </summary>
    public sealed record WireGuardResponseMessage
    {
        /// <summary>The responder's locally-chosen session index (little-endian on the wire).</summary>
        public required uint SenderIndex { get; init; }

        /// <summary>The initiator's session index, echoed back so the initiator can route the reply.</summary>
        public required uint ReceiverIndex { get; init; }

        /// <summary>The responder's ephemeral X25519 public key (32 bytes, sent in the clear).</summary>
        public required byte[] UnencryptedEphemeral { get; init; }

        /// <summary>The empty AEAD payload: 0 ciphertext bytes + a 16-byte tag binding the handshake transcript.</summary>
        public required byte[] EncryptedNothing { get; init; }

        /// <summary>mac1 (keyed BLAKE2s, 16 bytes). Computed/verified in V3.c; zero before that.</summary>
        public byte[] Mac1 { get; init; } = new byte[WireGuardConstants.MacLength];

        /// <summary>mac2 (cookie MAC, 16 bytes). Computed/verified in V3.c; zero when no cookie is in use.</summary>
        public byte[] Mac2 { get; init; } = new byte[WireGuardConstants.MacLength];
    }
}
