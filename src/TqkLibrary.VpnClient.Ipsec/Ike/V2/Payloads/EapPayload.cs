using TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>
    /// EAP payload (RFC 7296 §3.16): carries one EAP packet (RFC 3748 §4 — Code | Identifier | Length |
    /// [Type | Type-Data]) verbatim. IKEv2 wraps EAP for password-style authentication (EAP-MSCHAPv2);
    /// the EAP method state machine parses/builds <see cref="Message"/>.
    /// </summary>
    public sealed class EapPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Eap;

        /// <summary>The full EAP packet bytes, starting at the EAP Code field.</summary>
        public byte[] Message { get; set; } = Array.Empty<byte>();

        /// <summary>The EAP Code (Request/Response/Success/Failure), or <see cref="EapCode.None"/> when empty.</summary>
        public EapCode Code => Message.Length >= 1 ? (EapCode)Message[0] : EapCode.None;

        /// <summary>The EAP Identifier that ties a Response to its Request (0 when empty).</summary>
        public byte Identifier => Message.Length >= 2 ? Message[1] : (byte)0;

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output) => output.AddRange(Message);

        internal static EapPayload Parse(ReadOnlySpan<byte> body) => new() { Message = body.ToArray() };
    }
}
