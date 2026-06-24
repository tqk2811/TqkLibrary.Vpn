namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// REGISTER_SUPER_ACK body (<c>n2n_REGISTER_SUPER_ACK_t</c>) — the supernode's reply accepting an edge. Wire layout
    /// after the common header:
    /// <c>cookie(4 BE) ‖ srcMac(6) ‖ dev_addr(5) ‖ lifetime(2 BE) ‖ sock ‖ auth ‖ num_sn(1) ‖ key_time(4 BE)</c>,
    /// followed by <c>num_sn</c> additional supernode sockets the edge can fail over to. The <c>sock</c> here is always
    /// present (it echoes the edge's public socket as seen by the supernode), so it is not gated on a flag.
    /// </summary>
    public sealed class N2nRegisterSuperAck
    {
        /// <summary>Cookie copied from the edge's REGISTER_SUPER.</summary>
        public uint Cookie { get; init; }

        /// <summary>The supernode's own MAC (6 bytes).</summary>
        public byte[] SrcMac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>The subnet the supernode assigned to the edge.</summary>
        public N2nIpSubnet DevAddr { get; init; } = N2nIpSubnet.Unset;

        /// <summary>Registration lifetime in seconds before the edge must re-register.</summary>
        public ushort Lifetime { get; init; }

        /// <summary>The edge's public socket as the supernode observed it.</summary>
        public N2nSock Sock { get; init; } = new N2nSock();

        /// <summary>Authentication block echoed/answered by the supernode.</summary>
        public N2nAuth Auth { get; init; } = new N2nAuth();

        /// <summary>Number of extra supernode sockets that follow in <see cref="ExtraSupernodes"/>.</summary>
        public byte NumSn { get; init; }

        /// <summary>The additional supernode sockets the edge may use as fallbacks.</summary>
        public N2nSock[] ExtraSupernodes { get; init; } = Array.Empty<N2nSock>();

        /// <summary>Key-rotation time for dynamic header keys.</summary>
        public uint KeyTime { get; init; }
    }
}
