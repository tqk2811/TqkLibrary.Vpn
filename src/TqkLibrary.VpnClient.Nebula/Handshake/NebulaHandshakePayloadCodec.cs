using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Handshake.Models;

namespace TqkLibrary.VpnClient.Nebula.Handshake
{
    /// <summary>
    /// Marshals and parses the Nebula handshake payload that travels inside the Noise message. The outer message is
    /// <c>NebulaHandshake { Details=1: NebulaHandshakeDetails, Hmac=2: bytes }</c>; the IX path never sets Hmac.
    /// </summary>
    public sealed class NebulaHandshakePayloadCodec
    {
        const int HandshakeDetails = 1;
        const int HandshakeHmac = 2;

        const int DetailsCert = 1;
        const int DetailsInitiatorIndex = 2;
        const int DetailsResponderIndex = 3;
        const int DetailsTime = 5;

        /// <summary>Marshals <paramref name="details"/> into the full <c>NebulaHandshake</c> payload bytes.</summary>
        public byte[] Marshal(NebulaHandshakeDetails details)
        {
            if (details is null) throw new ArgumentNullException(nameof(details));

            var inner = new ProtobufWriter();
            if (details.Cert.Length != 0) inner.WriteLengthDelimitedField(DetailsCert, details.Cert);
            if (details.InitiatorIndex != 0) inner.WriteVarintField(DetailsInitiatorIndex, details.InitiatorIndex);
            if (details.ResponderIndex != 0) inner.WriteVarintField(DetailsResponderIndex, details.ResponderIndex);
            if (details.Time != 0) inner.WriteVarintField(DetailsTime, details.Time);

            var outer = new ProtobufWriter();
            outer.WriteLengthDelimitedField(HandshakeDetails, inner.ToArray());
            return outer.ToArray();
        }

        /// <summary>Parses a <c>NebulaHandshake</c> payload, returning its details (Hmac is ignored on the IX path).</summary>
        public NebulaHandshakeDetails Unmarshal(ReadOnlySpan<byte> data)
        {
            var details = new NebulaHandshakeDetails();
            var r = new ProtobufReader(data);
            while (r.TryReadTag(out int field, out int wireType))
            {
                switch (field)
                {
                    case HandshakeDetails when wireType == 2:
                        ParseDetails(r.ReadLengthDelimited(), details);
                        break;
                    case HandshakeHmac when wireType == 2:
                        r.ReadLengthDelimited(); // ignored on the IX path
                        break;
                    default:
                        r.SkipField(wireType);
                        break;
                }
            }
            return details;
        }

        static void ParseDetails(ReadOnlySpan<byte> data, NebulaHandshakeDetails details)
        {
            var r = new ProtobufReader(data);
            while (r.TryReadTag(out int field, out int wireType))
            {
                switch (field)
                {
                    case DetailsCert when wireType == 2:
                        details.Cert = r.ReadLengthDelimited().ToArray();
                        break;
                    case DetailsInitiatorIndex when wireType == 0:
                        details.InitiatorIndex = (uint)r.ReadVarint();
                        break;
                    case DetailsResponderIndex when wireType == 0:
                        details.ResponderIndex = (uint)r.ReadVarint();
                        break;
                    case DetailsTime when wireType == 0:
                        details.Time = r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wireType);
                        break;
                }
            }
        }
    }
}
