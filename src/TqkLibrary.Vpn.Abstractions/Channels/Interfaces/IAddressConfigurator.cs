using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// Obtains an IP configuration (address / prefix / gateway-routes / DNS / MTU) for a host on an L2 segment —
    /// the DHCP/SLAAC slot of an <c>EthernetAdapter</c> (design 00 §5). Lives behind the L2 boundary.
    /// Returns the shared <see cref="TunnelConfig"/> model (same shape IPCP/config-push already produce).
    /// Implementations: DHCPv4 client (L2.5) and SLAAC + DHCPv6 client (L2.6).
    /// </summary>
    public interface IAddressConfigurator
    {
        /// <summary>
        /// Acquires (or renews) the host's address configuration, e.g. by running a DHCP exchange or processing
        /// a Router Advertisement. The resulting <see cref="TunnelConfig"/> feeds the host's userspace IP stack.
        /// </summary>
        ValueTask<TunnelConfig> ConfigureAsync(CancellationToken cancellationToken = default);
    }
}
