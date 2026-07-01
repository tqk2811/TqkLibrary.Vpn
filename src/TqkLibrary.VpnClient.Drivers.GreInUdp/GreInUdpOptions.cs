using TqkLibrary.VpnClient.IpEncap.Gre;

namespace TqkLibrary.VpnClient.Drivers.GreInUdp
{
    /// <summary>
    /// Static configuration for a <see cref="GreInUdpConnection"/>: the UDP destination port carrying the GRE header,
    /// the inner MTU, and the (optional) RFC 2890 GRE options. GRE-in-UDP (RFC 8086) has no negotiation — every
    /// parameter is fixed up front by the caller (the remote gateway is the <c>VpnEndpoint.Host</c> passed to the driver).
    /// </summary>
    public sealed class GreInUdpOptions
    {
        /// <summary>The UDP destination port the GRE header is carried on. Default 4754 (IANA "GRE-in-UDP", RFC 8086).</summary>
        public int Port { get; init; } = 4754;

        /// <summary>Inner-packet MTU advertised to the IP stack (outer-IP + UDP + GRE overhead already deducted). Default 1400.</summary>
        public int Mtu { get; init; } = 1400;

        /// <summary>
        /// Outbound GRE options (RFC 2890 Key / Sequence / Checksum). When null a minimal RFC 2784 GRE header is
        /// emitted; the channel's MTU is always taken from <see cref="Mtu"/> regardless of any value set on this object.
        /// </summary>
        public GreTunnelOptions? Gre { get; init; }
    }
}
