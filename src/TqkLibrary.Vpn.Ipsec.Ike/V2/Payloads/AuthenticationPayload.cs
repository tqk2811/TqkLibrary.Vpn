using TqkLibrary.Vpn.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.V2.Payloads
{
    /// <summary>AUTH payload (RFC 7296 §3.8): Auth Method(1) | RESERVED(3) | Authentication Data.</summary>
    public sealed class AuthenticationPayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Authentication;

        /// <summary>The authentication method (Shared Key for PSK).</summary>
        public IkeAuthMethod Method { get; set; } = IkeAuthMethod.SharedKey;

        /// <summary>The authentication data (the PSK MIC for <see cref="IkeAuthMethod.SharedKey"/>).</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)Method);
            output.Add(0); output.Add(0); output.Add(0); // reserved
            output.AddRange(Data);
        }

        internal static AuthenticationPayload Parse(ReadOnlySpan<byte> body)
            => new()
            {
                Method = (IkeAuthMethod)body[0],
                Data = body.Slice(4).ToArray(),
            };
    }
}
