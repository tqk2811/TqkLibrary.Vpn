using System.Net;

namespace TqkLibrary.VpnClient.Ethernet.Models
{
    /// <summary>
    /// What <see cref="NdiscResolver"/> learned from the most recent Router Advertisement (RFC 4861 §4.2): the default
    /// router (gateway) and, if the RA carried a Prefix Information option, the on-link/SLAAC prefix. This is the
    /// hand-off NDISC gives the IPv6 address-configuration layer (SLAAC, L2.6 / P1.1): a global address is formed from
    /// <see cref="Prefix"/> when <see cref="PrefixAutonomous"/> is set, and <see cref="Router"/> becomes the v6 gateway.
    /// </summary>
    /// <remarks>Plain immutable class (constructor-set, read-only) so it compiles on <c>netstandard2.0</c>.</remarks>
    public sealed class RouterAdvertisementInfo
    {
        /// <summary>The advertising router's link-local source address — the IPv6 default gateway.</summary>
        public IPAddress Router { get; }

        /// <summary>The router's link-layer (MAC) address from the Source Link-Layer Address option, if it carried one.</summary>
        public MacAddress? RouterMac { get; }

        /// <summary>Router Lifetime in seconds (RFC 4861 §4.2): zero means the router is not a default router.</summary>
        public ushort RouterLifetimeSeconds { get; }

        /// <summary>True if the M (Managed) flag is set — addresses should come from stateful DHCPv6.</summary>
        public bool Managed { get; }

        /// <summary>True if the O (Other) flag is set — other configuration (DNS, …) comes from DHCPv6.</summary>
        public bool OtherConfig { get; }

        /// <summary>The advertised prefix (RFC 4861 §4.6.2), or <c>null</c> if the RA carried no Prefix Information option.</summary>
        public IPAddress? Prefix { get; }

        /// <summary>The advertised prefix length in bits (typically 64 for SLAAC).</summary>
        public byte PrefixLength { get; }

        /// <summary>True if the prefix's On-Link (L) flag is set.</summary>
        public bool PrefixOnLink { get; }

        /// <summary>True if the prefix's Autonomous (A) flag is set — it may be used to form a SLAAC address.</summary>
        public bool PrefixAutonomous { get; }

        /// <summary>The prefix's Valid Lifetime in seconds (RFC 4861 §4.6.2).</summary>
        public uint PrefixValidLifetime { get; }

        /// <summary>The prefix's Preferred Lifetime in seconds (RFC 4861 §4.6.2).</summary>
        public uint PrefixPreferredLifetime { get; }

        /// <summary>Creates the parsed view of a Router Advertisement.</summary>
        public RouterAdvertisementInfo(IPAddress router, MacAddress? routerMac, ushort routerLifetimeSeconds, bool managed, bool otherConfig, IPAddress? prefix, byte prefixLength, bool prefixOnLink, bool prefixAutonomous, uint prefixValidLifetime, uint prefixPreferredLifetime)
        {
            Router = router;
            RouterMac = routerMac;
            RouterLifetimeSeconds = routerLifetimeSeconds;
            Managed = managed;
            OtherConfig = otherConfig;
            Prefix = prefix;
            PrefixLength = prefixLength;
            PrefixOnLink = prefixOnLink;
            PrefixAutonomous = prefixAutonomous;
            PrefixValidLifetime = prefixValidLifetime;
            PrefixPreferredLifetime = prefixPreferredLifetime;
        }
    }
}
