using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.DataChannel
{
    /// <summary>
    /// Resolves an overlay next-hop IP to its Ethernet MAC the ZeroTier way: ZeroTier <b>computes</b> a node's per-network
    /// MAC from its 40-bit address and the network id (<c>MAC::fromAddress</c>) rather than ARPing for it, so there is no
    /// ARP exchange on a ZeroTier L2 segment. In the supported single-upstream topology the client carries every overlay
    /// frame to the one peer it is connected to (the node / controller, which relays), so every reachable next-hop maps to
    /// that peer's derived MAC. This replaces the userspace <c>ArpResolver</c> for the ZeroTier data plane.
    /// </summary>
    public sealed class ZeroTierNeighborResolver : INeighborResolver
    {
        readonly byte[] _peerMac;

        /// <summary>Builds a resolver that maps every next-hop to <paramref name="peerAddress"/>'s MAC on <paramref name="network"/>.</summary>
        public ZeroTierNeighborResolver(ZeroTierAddress peerAddress, NetworkId network)
        {
            _peerMac = new Vl2FrameCodec().DeriveMac(peerAddress, network);
        }

        /// <inheritdoc/>
        public ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
        {
            if (nextHop is null || nextHop.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return new ValueTask<ReadOnlyMemory<byte>?>((ReadOnlyMemory<byte>?)null);
            // Every in-overlay next-hop is reached through the connected peer; ZeroTier derives the peer's MAC, no ARP.
            return new ValueTask<ReadOnlyMemory<byte>?>(_peerMac);
        }
    }
}
