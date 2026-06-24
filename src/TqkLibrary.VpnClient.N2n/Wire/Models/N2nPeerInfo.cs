namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// PEER_INFO body (<c>n2n_PEER_INFO_t</c>) — the supernode's answer to a QUERY_PEER, telling an edge how to reach a
    /// peer. Wire layout after the common header:
    /// <c>aflags(2 BE) ‖ mac(6) ‖ sock ‖ preferred_sock ‖ load(4 BE) ‖ uptime(4 BE)</c>.
    /// (n2n v3 also carries a version string; this codec reads/writes the fixed numeric fields and treats any trailing
    /// bytes as opaque, since the driver only needs the peer socket.)
    /// </summary>
    public sealed class N2nPeerInfo
    {
        /// <summary>Answer flags (e.g. whether the queried peer is known).</summary>
        public ushort AFlags { get; init; }

        /// <summary>The queried peer's MAC (6 bytes).</summary>
        public byte[] Mac { get; init; } = new byte[N2nConstants.MacSize];

        /// <summary>The peer's socket as the supernode knows it.</summary>
        public N2nSock Sock { get; init; } = new N2nSock();

        /// <summary>The peer's preferred (local/LAN) socket for same-network P2P.</summary>
        public N2nSock PreferredSock { get; init; } = new N2nSock();

        /// <summary>Supernode load metric.</summary>
        public uint Load { get; init; }

        /// <summary>Peer uptime in seconds.</summary>
        public uint Uptime { get; init; }
    }
}
