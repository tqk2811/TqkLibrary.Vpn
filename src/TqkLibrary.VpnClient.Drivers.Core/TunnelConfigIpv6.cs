using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Core
{
    /// <summary>
    /// Merges the global-IPv6 fragment a PPP driver obtains over the link (SLAAC/DHCPv6, P1.1) into the
    /// <see cref="TunnelConfig"/> it returns. Shared by the SSTP and L2TP/IPsec drivers, which both run PPP and surface a
    /// global address the same way.
    /// </summary>
    public static class TunnelConfigIpv6
    {
        /// <summary>
        /// Copies the prefix length, IPv6 DNS servers and the <c>::/0</c> default route from <paramref name="v6"/> into
        /// <paramref name="target"/>. The global address itself is set by the caller from the connection. No-op when no
        /// global address was acquired (only the IPV6CP link-local is available).
        /// </summary>
        public static void ApplyGlobalIpv6(TunnelConfig target, TunnelConfig? v6)
        {
            if (v6?.AssignedAddressV6 == null)
                return;
            target.PrefixLengthV6 = v6.PrefixLengthV6;
            foreach (IPAddress dns in v6.DnsServers)
                if (dns.AddressFamily == AddressFamily.InterNetworkV6)
                    target.DnsServers.Add(dns);
            foreach (string route in v6.Routes)
                target.Routes.Add(route);
        }
    }
}
