using System.Net;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Config
{
    /// <summary>
    /// A static ZeroTier client configuration — the parts of a node's <c>identity.secret</c> + a network membership the
    /// client needs to join one VL2 network. This node's <see cref="Identity"/> (with its private key) drives the
    /// Curve25519 agreement that secures VL1; <see cref="PeerIdentity"/> is the upstream node / controller this client
    /// peers with directly (its public key — the same agreement, the other half). <see cref="NetworkId"/> selects the
    /// VL2 network to join.
    /// <para>
    /// The overlay address can come from the controller's network config (set <see cref="OverlayAddress"/> null to adopt
    /// the controller-assigned IP) or be pinned statically (set it to skip the wait / for a controller that does not push
    /// an address). A self-hosted controller this client peers with directly is the supported lab topology; planet/moon
    /// root discovery is out of scope (peer with the controller node directly).
    /// </para>
    /// </summary>
    public sealed class ZeroTierConfig
    {
        /// <summary>This node's identity, including its 64-byte private key (Curve25519 ECDH || Ed25519). Required.</summary>
        public required ZeroTierIdentity Identity { get; init; }

        /// <summary>The upstream node / controller this client peers with — its public identity (address + 64-byte public key). Required.</summary>
        public required ZeroTierIdentity PeerIdentity { get; init; }

        /// <summary>The VL2 network id to join (the controller is the high 40 bits). Required.</summary>
        public required NetworkId NetworkId { get; init; }

        /// <summary>
        /// The static overlay IPv4 address to use on the VL2 segment, or null to adopt the controller-assigned address
        /// from the network config. Defaults to null (controller-assigned).
        /// </summary>
        public IPAddress? OverlayAddress { get; init; }

        /// <summary>The overlay subnet prefix length when <see cref="OverlayAddress"/> is pinned statically. Defaults to 24.</summary>
        public int PrefixLength { get; init; } = 24;

        /// <summary>DNS servers to use inside the tunnel; empty when none is configured.</summary>
        public IReadOnlyList<IPAddress> DnsServers { get; init; } = Array.Empty<IPAddress>();

        /// <summary>The overlay routes reachable through the tunnel (CIDR text); the overlay subnet is added when empty.</summary>
        public IReadOnlyList<string> Routes { get; init; } = Array.Empty<string>();

        /// <summary>The tunnel MTU; defaults to <see cref="ZeroTierDriverConstants.DefaultMtu"/>.</summary>
        public int Mtu { get; init; } = ZeroTierDriverConstants.DefaultMtu;

        /// <summary>
        /// How long to wait for the controller's network config (assigned IP + COM) before giving up; the VL1 session is
        /// already up by then. Defaults to 15 s. When <see cref="OverlayAddress"/> is pinned the wait is skipped.
        /// </summary>
        public TimeSpan NetworkConfigTimeout { get; init; } = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Projects the static portion of this configuration onto a <see cref="TunnelConfig"/> using the supplied
        /// effective overlay address / prefix (either the pinned address or the one the controller assigned). DNS, routes
        /// and MTU come from this config. The bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        public TunnelConfig ToTunnelConfig(IPAddress overlayAddress, int prefixLength)
        {
            var config = new TunnelConfig
            {
                AssignedAddress = overlayAddress,
                PrefixLength = prefixLength,
                Mtu = Mtu,
            };
            foreach (IPAddress dns in DnsServers) config.DnsServers.Add(dns);
            if (Routes.Count > 0)
            {
                foreach (string route in Routes) config.Routes.Add(route);
            }
            else
            {
                config.Routes.Add($"{overlayAddress}/{prefixLength}");
            }
            return config;
        }
    }
}
