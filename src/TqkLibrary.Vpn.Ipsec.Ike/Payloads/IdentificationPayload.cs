using TqkLibrary.Vpn.Ipsec.Ike.Enums;

namespace TqkLibrary.Vpn.Ipsec.Ike.Payloads
{
    /// <summary>
    /// An IDi or IDr identification payload (RFC 7296 §3.5): ID Type(1) | RESERVED(3) | Identification Data.
    /// The "rest of ID" (the body) is what feeds the AUTH signature, so it is exposed via <see cref="BodyBytes"/>.
    /// </summary>
    public sealed class IdentificationPayload : IkePayload
    {
        /// <summary>True for IDi (initiator), false for IDr (responder).</summary>
        public bool IsInitiator { get; set; } = true;

        /// <inheritdoc/>
        public override IkePayloadType Type => IsInitiator ? IkePayloadType.IdInitiator : IkePayloadType.IdResponder;

        /// <summary>The identification type.</summary>
        public IkeIdType IdType { get; set; } = IkeIdType.KeyId;

        /// <summary>The identification data (e.g. an IPv4 address or a string).</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)IdType);
            output.Add(0); output.Add(0); output.Add(0); // reserved
            output.AddRange(Data);
        }

        /// <summary>The payload body (ID Type + reserved + data) — the "RestOfID" octets signed by AUTH.</summary>
        public byte[] BodyBytes()
        {
            var output = new List<byte>(4 + Data.Length);
            WriteBody(output);
            return output.ToArray();
        }

        internal static IdentificationPayload Parse(ReadOnlySpan<byte> body, bool isInitiator)
            => new()
            {
                IsInitiator = isInitiator,
                IdType = (IkeIdType)body[0],
                Data = body.Slice(4).ToArray(),
            };
    }
}
