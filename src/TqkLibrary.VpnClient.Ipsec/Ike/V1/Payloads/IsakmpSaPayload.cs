using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Models;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads
{
    /// <summary>
    /// An ISAKMP Security Association payload (RFC 2408 §3.4): DOI(4) + Situation(4) + proposals. Proposals and
    /// transforms reuse the generic payload header (Next Payload = 2/3 to chain "more", 0 to end).
    /// </summary>
    public sealed class IsakmpSaPayload : IsakmpPayload
    {
        /// <inheritdoc/>
        public override IsakmpPayloadType Type => IsakmpPayloadType.SecurityAssociation;

        /// <summary>The Domain of Interpretation (IPSEC_DOI = 1).</summary>
        public uint Doi { get; set; } = IkeV1Constants.IpsecDoi;

        /// <summary>The situation (SIT_IDENTITY_ONLY = 1).</summary>
        public uint Situation { get; set; } = IkeV1Constants.SituationIdentityOnly;

        /// <summary>The proposals.</summary>
        public List<IsakmpProposal> Proposals { get; } = new();

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            WriteUInt32(output, Doi);
            WriteUInt32(output, Situation);
            for (int p = 0; p < Proposals.Count; p++)
                WriteProposal(output, Proposals[p], isLast: p == Proposals.Count - 1);
        }

        static void WriteProposal(List<byte> output, IsakmpProposal proposal, bool isLast)
        {
            int start = output.Count;
            output.Add((byte)(isLast ? IsakmpPayloadType.None : IsakmpPayloadType.Proposal));
            output.Add(0); // reserved
            output.Add(0); output.Add(0); // length placeholder
            output.Add(proposal.Number);
            output.Add(proposal.ProtocolId);
            output.Add((byte)proposal.Spi.Length);
            output.Add((byte)proposal.Transforms.Count);
            output.AddRange(proposal.Spi);
            for (int t = 0; t < proposal.Transforms.Count; t++)
                WriteTransform(output, proposal.Transforms[t], isLast: t == proposal.Transforms.Count - 1);
            PatchLength(output, start);
        }

        static void WriteTransform(List<byte> output, IsakmpTransform transform, bool isLast)
        {
            int start = output.Count;
            output.Add((byte)(isLast ? IsakmpPayloadType.None : IsakmpPayloadType.Transform));
            output.Add(0); // reserved
            output.Add(0); output.Add(0); // length placeholder
            output.Add(transform.Number);
            output.Add(transform.TransformId);
            output.Add(0); output.Add(0); // reserved2
            foreach (IsakmpAttribute attribute in transform.Attributes) attribute.Write(output);
            PatchLength(output, start);
        }

        internal static IsakmpSaPayload Parse(ReadOnlySpan<byte> body)
        {
            var sa = new IsakmpSaPayload
            {
                Doi = ReadUInt32(body, 0),
                Situation = ReadUInt32(body, 4),
            };
            int offset = 8;
            while (offset + 8 <= body.Length)
            {
                byte more = body[offset];
                int propLength = (body[offset + 2] << 8) | body[offset + 3];
                if (propLength < 8 || offset + propLength > body.Length) break;
                ReadOnlySpan<byte> prop = body.Slice(offset, propLength);

                var proposal = new IsakmpProposal { Number = prop[4], ProtocolId = prop[5] };
                int spiSize = prop[6];
                int transformCount = prop[7];
                int cursor = 8;
                proposal.Spi = prop.Slice(cursor, spiSize).ToArray();
                cursor += spiSize;

                for (int i = 0; i < transformCount && cursor + 8 <= prop.Length; i++)
                {
                    int transformLength = (prop[cursor + 2] << 8) | prop[cursor + 3];
                    if (transformLength < 8 || cursor + transformLength > prop.Length) break;
                    var transform = new IsakmpTransform { Number = prop[cursor + 4], TransformId = prop[cursor + 5] };
                    int attrOffset = cursor + 8;
                    while (attrOffset + 4 <= cursor + transformLength)
                    {
                        IsakmpAttribute attribute = IsakmpAttribute.Parse(prop.Slice(attrOffset), out int consumed);
                        transform.Attributes.Add(attribute);
                        attrOffset += consumed;
                    }
                    proposal.Transforms.Add(transform);
                    cursor += transformLength;
                }

                sa.Proposals.Add(proposal);
                offset += propLength;
                if (more == (byte)IsakmpPayloadType.None) break;
            }
            return sa;
        }

        static void PatchLength(List<byte> output, int start)
        {
            int length = output.Count - start;
            output[start + 2] = (byte)(length >> 8);
            output[start + 3] = (byte)length;
        }

        static void WriteUInt32(List<byte> output, uint value)
        {
            output.Add((byte)(value >> 24)); output.Add((byte)(value >> 16));
            output.Add((byte)(value >> 8)); output.Add((byte)value);
        }

        static uint ReadUInt32(ReadOnlySpan<byte> data, int offset)
            => (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
    }
}
