namespace TqkLibrary.VpnClient.WireGuard.Handshake.Models
{
    /// <summary>
    /// The pair of 32-byte transport (data-channel) keys produced by the Noise <c>Split</c> at the end of the
    /// handshake (whitepaper §5.4.4). <see cref="SendKey"/> encrypts this peer's outbound transport packets and
    /// <see cref="ReceiveKey"/> decrypts inbound ones. The initiator's <c>(send, receive)</c> is exactly the
    /// responder's <c>(receive, send)</c>: both derive the same ordered pair from the shared chaining key, then the
    /// responder swaps the roles. Consumed by the data channel in V3.d.
    /// </summary>
    public sealed record WireGuardTransportKeys
    {
        /// <summary>Key used to AEAD-seal this peer's outbound transport packets (32 bytes).</summary>
        public required byte[] SendKey { get; init; }

        /// <summary>Key used to AEAD-open this peer's inbound transport packets (32 bytes).</summary>
        public required byte[] ReceiveKey { get; init; }
    }
}
