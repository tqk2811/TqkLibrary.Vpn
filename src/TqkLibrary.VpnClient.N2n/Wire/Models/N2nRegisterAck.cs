namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// REGISTER_ACK body (<c>n2n_REGISTER_ACK_t</c>) — the reply to an edge↔edge REGISTER. Wire layout after the common
    /// header: <c>cookie(4 BE) ‖ srcMac(6) ‖ dstMac(6) ‖ [sock — only when N2N_FLAGS_SOCKET]</c>.
    /// </summary>
    public sealed class N2nRegisterAck
    {
        /// <summary>Cookie copied from the REGISTER being acknowledged.</summary>
        public uint Cookie { get; init; }

        /// <summary>Sender edge MAC (6 bytes) — the edge that received the REGISTER.</summary>
        public byte[] SrcMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Target edge MAC (6 bytes) — the original registrant.</summary>
        public byte[] DstMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Optional advertised socket (present only when <see cref="Enums.N2nFlags.Socket"/> is set).</summary>
        public N2nSock? Sock { get; init; }
    }
}
