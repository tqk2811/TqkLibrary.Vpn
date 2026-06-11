using System.Net;

namespace TqkLibrary.Vpn.Abstractions.Channels.Interfaces
{
    /// <summary>
    /// Resolves a next-hop IP address to its link-layer (MAC) address — the ARP/NDISC slot of an
    /// <c>EthernetAdapter</c> (design 00 §5). Lives behind the L2 boundary; the userspace IP stack never sees it.
    /// MAC is raw bytes (6 octets) to keep <c>Abstractions</c> free of any L2 codec dependency, matching
    /// <see cref="IEthernetChannel.LinkAddress"/>. Implementations: ARP (L2.3, IPv4) and NDISC (L2.4, IPv6).
    /// </summary>
    public interface INeighborResolver
    {
        /// <summary>
        /// Resolves <paramref name="nextHop"/> to its MAC (6 bytes), or <c>null</c> if it cannot be reached.
        /// May send an ARP/NDISC request and await the reply.
        /// </summary>
        ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default);
    }
}
