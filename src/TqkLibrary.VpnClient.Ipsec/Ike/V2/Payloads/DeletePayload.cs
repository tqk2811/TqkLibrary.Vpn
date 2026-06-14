using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads
{
    /// <summary>
    /// Delete payload (RFC 7296 §3.11): tears down an SA. Layout: Protocol ID(1) | SPI Size(1) | Num SPIs(2) | SPIs.
    /// For an ESP CHILD_SA the protocol is <see cref="IkeProtocolId.Esp"/> with the 4-byte SPIs to remove; deleting
    /// the IKE SA itself uses <see cref="IkeProtocolId.Ike"/> with SPI Size 0 and no SPIs.
    /// </summary>
    public sealed class DeletePayload : IkePayload
    {
        /// <inheritdoc/>
        public override IkePayloadType Type => IkePayloadType.Delete;

        /// <summary>The protocol of the SA(s) being deleted (IKE, ESP, or AH).</summary>
        public IkeProtocolId ProtocolId { get; set; } = IkeProtocolId.Esp;

        /// <summary>The SPIs to delete (each <see cref="SpiSize"/> bytes); empty when deleting the IKE SA.</summary>
        public List<byte[]> Spis { get; } = new();

        /// <summary>The byte length of each SPI (4 for ESP/AH, 0 for the IKE SA).</summary>
        public byte SpiSize => Spis.Count > 0 ? (byte)Spis[0].Length : (byte)0;

        /// <summary>Deletes an ESP CHILD_SA identified by the inbound SPI we asked the peer to send to.</summary>
        public static DeletePayload Esp(byte[] spi)
        {
            var delete = new DeletePayload { ProtocolId = IkeProtocolId.Esp };
            delete.Spis.Add(spi);
            return delete;
        }

        /// <summary>Deletes the IKE SA itself (no SPIs, per RFC 7296 §3.11).</summary>
        public static DeletePayload Ike() => new() { ProtocolId = IkeProtocolId.Ike };

        /// <inheritdoc/>
        public override void WriteBody(List<byte> output)
        {
            output.Add((byte)ProtocolId);
            output.Add(SpiSize);
            IkeBuffer.WriteUInt16(output, (ushort)Spis.Count);
            foreach (byte[] spi in Spis)
                output.AddRange(spi);
        }

        internal static DeletePayload Parse(ReadOnlySpan<byte> body)
        {
            var delete = new DeletePayload { ProtocolId = (IkeProtocolId)body[0] };
            int spiSize = body[1];
            int count = IkeBuffer.ReadUInt16(body, 2);
            int offset = 4;
            for (int i = 0; i < count && spiSize > 0 && offset + spiSize <= body.Length; i++)
            {
                delete.Spis.Add(body.Slice(offset, spiSize).ToArray());
                offset += spiSize;
            }
            return delete;
        }
    }
}
