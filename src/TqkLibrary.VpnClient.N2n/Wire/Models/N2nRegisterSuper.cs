namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// REGISTER_SUPER body (<c>n2n_REGISTER_SUPER_t</c>) — an edge registering with a supernode. Wire layout after the
    /// common header:
    /// <c>cookie(4 BE) ‖ edgeMac(6) ‖ [sock — only when N2N_FLAGS_SOCKET] ‖ dev_addr(5) ‖ dev_desc(16) ‖ auth ‖ key_time(4 BE)</c>.
    /// The supernode replies with REGISTER_SUPER_ACK on success or REGISTER_SUPER_NAK on rejection.
    /// </summary>
    public sealed class N2nRegisterSuper
    {
        /// <summary>Per-request cookie echoed back in the ACK so the edge can correlate the reply.</summary>
        public uint Cookie { get; init; }

        /// <summary>The registering edge's MAC address (6 bytes).</summary>
        public byte[] EdgeMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>Optional advertised socket (present only when <see cref="Enums.N2nFlags.Socket"/> is set on the header).</summary>
        public N2nSock? Sock { get; init; }

        /// <summary>Requested device subnet (usually <see cref="N2nIpSubnet.Unset"/> to let the supernode assign).</summary>
        public N2nIpSubnet DevAddr { get; init; } = N2nIpSubnet.Unset;

        /// <summary>Device description (≤ 16 ASCII bytes; null-padded).</summary>
        public string DevDesc { get; init; } = string.Empty;

        /// <summary>Authentication block (simple-id challenge by default).</summary>
        public N2nAuth Auth { get; init; } = N2nAuth.SimpleIdRandom();

        /// <summary>Key-rotation time for dynamic header keys (0 when header encryption is off).</summary>
        public uint KeyTime { get; init; }
    }
}
