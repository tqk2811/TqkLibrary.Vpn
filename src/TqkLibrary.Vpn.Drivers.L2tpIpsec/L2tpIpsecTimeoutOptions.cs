namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>
    /// Tunable handshake/keepalive timeouts for an <see cref="L2tpIpsecConnection"/>: how persistently the IKE
    /// exchanges and the L2TP control channel retry before declaring the gateway unresponsive. The defaults match the
    /// values that used to be hard-coded; tighten them to fail fast, or loosen them for high-latency links.
    /// </summary>
    public sealed class L2tpIpsecTimeoutOptions
    {
        /// <summary>How long to wait for a reply to each IKE message before resending it (Main/Quick Mode + rekey).</summary>
        public TimeSpan IkeRetransmitInterval { get; set; } = TimeSpan.FromSeconds(2.5);

        /// <summary>How many times an IKE message is sent before giving up with a <see cref="TqkLibrary.Vpn.Abstractions.Drivers.VpnNetworkTimeoutException"/>.</summary>
        public int IkeMaxAttempts { get; set; } = 5;

        /// <summary>How often the L2TP reliable control channel resends the head unacked message.</summary>
        public TimeSpan L2tpRetransmitInterval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>How many times an L2TP control message is retransmitted before the link is declared dead; 0 = unbounded.</summary>
        public int L2tpMaxRetransmits { get; set; } = 8;
    }
}
