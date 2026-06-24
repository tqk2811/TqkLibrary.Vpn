namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// REGISTER body (<c>n2n_REGISTER_t</c>) — an edge↔edge P2P registration used for UDP hole-punching. Wire layout
    /// after the common header:
    /// <c>cookie(4 BE) ‖ srcMac(6) ‖ dstMac(6) ‖ [sock — only when N2N_FLAGS_SOCKET] ‖ dev_addr(5) ‖ dev_desc(16)</c>.
    /// </summary>
    public sealed class N2nRegister
    {
        /// <summary>Per-request cookie echoed back in REGISTER_ACK.</summary>
        public uint Cookie { get; init; }

        /// <summary>Sender edge MAC (6 bytes).</summary>
        public byte[] SrcMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Target edge MAC (6 bytes).</summary>
        public byte[] DstMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Optional advertised socket (present only when <see cref="Enums.N2nFlags.Socket"/> is set).</summary>
        public N2nSock? Sock { get; init; }

        /// <summary>The sender's device subnet.</summary>
        public N2nIpSubnet DevAddr { get; init; } = N2nIpSubnet.Unset;

        /// <summary>Device description (≤ 16 ASCII bytes; null-padded).</summary>
        public string DevDesc { get; init; } = string.Empty;
    }
}
