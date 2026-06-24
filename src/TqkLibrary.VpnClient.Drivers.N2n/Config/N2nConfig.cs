using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.N2n.Config
{
    /// <summary>
    /// A static n2n edge configuration — the parts of an <c>edge.conf</c> the client needs to join one community and
    /// bring an L2 overlay up. n2n edges set their own static overlay IP (<c>-a</c>); the supernode does not push an
    /// address by default, so the tunnel address / prefix / routes / MTU are all known up front and map straight to a
    /// <see cref="TunnelConfig"/> (no DHCP). The edge registers under <see cref="Community"/> with <see cref="EdgeMac"/>
    /// (a random locally-administered MAC when left null) and carries frames through the selected
    /// <see cref="Transform"/>.
    /// </summary>
    public sealed class N2nConfig
    {
        /// <summary>The community name (≤ 20 ASCII bytes) every edge in this overlay shares. Required.</summary>
        public required string Community { get; init; }

        /// <summary>The static overlay IPv4 address this edge uses on the L2 segment (n2n <c>-a</c>). Required.</summary>
        public required IPAddress OverlayAddress { get; init; }

        /// <summary>The overlay subnet prefix length (n2n's edge netmask, e.g. /24). Defaults to 24.</summary>
        public int PrefixLength { get; init; } = 24;

        /// <summary>
        /// This edge's 6-byte MAC on the L2 segment. When null a random locally-administered unicast MAC is generated
        /// (what an n2n edge does when no <c>-m</c> is given).
        /// </summary>
        public byte[]? EdgeMac { get; init; }

        /// <summary>Which transform protects the PACKET payload (<see cref="N2nTransformKind.Null"/> by default).</summary>
        public N2nTransformKind Transform { get; init; } = N2nTransformKind.Null;

        /// <summary>
        /// The AES key (16/24/32 bytes) when <see cref="Transform"/> is <see cref="N2nTransformKind.Aes"/>; ignored for
        /// the NULL transform. This is the raw cipher key — n2n's Pearson-hash key derivation from the community password
        /// is out of scope (supply the key directly).
        /// </summary>
        public byte[]? AesKey { get; init; }

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>
        /// The overlay routes reachable through the tunnel (CIDR text). Defaults to the overlay subnet derived from
        /// <see cref="OverlayAddress"/>/<see cref="PrefixLength"/> when empty.
        /// </summary>
        public IReadOnlyList<string> Routes { get; init; } = Array.Empty<string>();

        /// <summary>The tunnel MTU; defaults to <see cref="N2nDriverConstants.DefaultMtu"/> (1290, the n2n default).</summary>
        public int Mtu { get; init; } = N2nDriverConstants.DefaultMtu;

        /// <summary>
        /// Projects this configuration onto a <see cref="TunnelConfig"/> — the same shape every driver hands to the
        /// userspace IP stack, filled directly from the static config rather than from any in-tunnel negotiation. The MTU
        /// reported here is the configured MTU; the bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        public TunnelConfig ToTunnelConfig()
        {
            var config = new TunnelConfig
            {
                AssignedAddress = OverlayAddress,
                PrefixLength = PrefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (Routes.Count > 0)
            {
                foreach (string route in Routes) config.Routes.Add(route);
            }
            else
            {
                config.Routes.Add($"{OverlayAddress}/{PrefixLength}");
            }
            return config;
        }
    }
}
