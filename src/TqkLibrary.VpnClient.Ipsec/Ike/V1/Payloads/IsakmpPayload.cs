using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads
{
    /// <summary>Base for an ISAKMP payload (RFC 2408): a 4-byte generic header (Next Payload, RESERVED, Length) + body.</summary>
    public abstract class IsakmpPayload
    {
        /// <summary>The payload type used in the preceding Next Payload field.</summary>
        public abstract IsakmpPayloadType Type { get; }

        /// <summary>Appends the payload body (after the 4-byte generic header) to <paramref name="output"/>.</summary>
        public abstract void WriteBody(List<byte> output);

        /// <summary>The payload body as a standalone array (used for the auth HASH inputs).</summary>
        public byte[] BodyBytes()
        {
            var output = new List<byte>();
            WriteBody(output);
            return output.ToArray();
        }
    }

    /// <summary>A payload whose body is carried verbatim (KE, Nonce, ID, Hash, Vendor ID, NAT-D, Notification…).</summary>
    public sealed class IsakmpRawPayload : IsakmpPayload
    {
        /// <inheritdoc/>
        public override IsakmpPayloadType Type { get; }

        /// <summary>The opaque payload body.</summary>
        public byte[] Body { get; }

        /// <summary>Creates a raw payload of the given type carrying <paramref name="body"/>.</summary>
        public IsakmpRawPayload(IsakmpPayloadType type, byte[] body)
        {
            Type = type;
            Body = body;
        }

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output) => output.AddRange(Body);
    }
}
