namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// PACKET body (<c>n2n_PACKET_t</c>) — an encapsulated L2 Ethernet frame. Wire layout after the common header:
    /// <c>srcMac(6) ‖ dstMac(6) ‖ [sock — only when N2N_FLAGS_SOCKET] ‖ compression(1) ‖ transform(1)</c>, then the
    /// (optionally transform-encrypted) Ethernet frame payload. <see cref="Payload"/> holds the inner Ethernet frame;
    /// the <see cref="N2n.N2nPacketCodec"/> applies the selected <see cref="Enums.N2nTransformId"/> to it.
    /// </summary>
    public sealed class N2nPacket
    {
        /// <summary>Source edge MAC (6 bytes).</summary>
        public byte[] SrcMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Destination edge MAC (6 bytes) — may be broadcast.</summary>
        public byte[] DstMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Optional advertised socket (present only when <see cref="Enums.N2nFlags.Socket"/> is set).</summary>
        public N2nSock? Sock { get; init; }

        /// <summary>Compression id applied to the payload (<c>N2N_COMPRESSION_ID_NONE</c> = 1 here — no compression).</summary>
        public byte Compression { get; init; } = 1;

        /// <summary>Transform id protecting the payload (<see cref="Enums.N2nTransformId"/>).</summary>
        public Enums.N2nTransformId Transform { get; init; } = Enums.N2nTransformId.Null;

        /// <summary>The inner Ethernet frame (plaintext at this level; the codec applies the transform).</summary>
        public byte[] Payload { get; init; } = Array.Empty<byte>();
    }
}
