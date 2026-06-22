using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Ppp.Ipv6
{
    /// <summary>
    /// Obtains a <b>global</b> IPv6 address over a PPP link after IPV6CP has brought up the link-local address (P1.1).
    /// IPV6CP (RFC 5072) only negotiates the interface identifier (link-local <c>fe80::/64</c>); a routable address comes
    /// from the server advertising a prefix on the link — exactly as a host on any other medium: a Router Advertisement
    /// (SLAAC, RFC 4862) or stateful DHCPv6 (RFC 8415), both carried as ordinary IPv6 packets over the PPP channel.
    /// </summary>
    public interface IPppIpv6Autoconfigurator
    {
        /// <summary>
        /// Solicits a Router Advertisement on <paramref name="channel"/> and forms a global address from its prefix and the
        /// IPV6CP <paramref name="interfaceId"/> (or leases one via DHCPv6 when the RA's Managed flag is set). Best-effort:
        /// returns the produced <see cref="TunnelConfig"/> (global address + prefix length + any IPv6 DNS + the <c>::/0</c>
        /// default route), or <c>null</c> when no router answers (the caller keeps the link-local from IPV6CP). The
        /// <paramref name="cancellationToken"/> firing (teardown) propagates as an <see cref="System.OperationCanceledException"/>.
        /// </summary>
        Task<TunnelConfig?> TryConfigureAsync(IPacketChannel channel, IPAddress linkLocal, byte[] interfaceId, CancellationToken cancellationToken = default);
    }
}
