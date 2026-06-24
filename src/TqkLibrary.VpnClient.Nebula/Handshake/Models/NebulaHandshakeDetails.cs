namespace TqkLibrary.VpnClient.Nebula.Handshake.Models
{
    /// <summary>
    /// The body of a Nebula handshake payload (<c>NebulaHandshakeDetails</c>, handshake.proto). Carried inside the
    /// Noise message payload. Field numbers: Cert=1, InitiatorIndex=2, ResponderIndex=3, Cookie=4 (deprecated),
    /// Time=5, CertVersion=8.
    /// </summary>
    public sealed class NebulaHandshakeDetails
    {
        /// <summary>
        /// The sender's marshaled <c>RawNebulaCertificate</c> with its <c>PublicKey</c> (details field 7) stripped —
        /// the static public key is already carried by the Noise <c>s</c> token, so it is removed here and recombined
        /// on receipt (field 1).
        /// </summary>
        public byte[] Cert { get; set; } = Array.Empty<byte>();

        /// <summary>The initiator's session index (field 2). Set in message 1.</summary>
        public uint InitiatorIndex { get; set; }

        /// <summary>The responder's session index (field 3). Set in message 2.</summary>
        public uint ResponderIndex { get; set; }

        /// <summary>Send time as Unix nanoseconds (field 5).</summary>
        public ulong Time { get; set; }
    }
}
