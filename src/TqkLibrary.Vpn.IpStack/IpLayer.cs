using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Dispatches IP-layer build and fragmentation to IPv4 or IPv6 by address family / version nibble, so the transport
    /// layer (TCP/UDP) and the stack stay address-family-agnostic — the segment/datagram format is identical, only the
    /// enclosing IP header and pseudo-header differ.
    /// </summary>
    public static class IpLayer
    {
        /// <summary>The IP version nibble of a raw packet (4 or 6).</summary>
        public static byte Version(ReadOnlySpan<byte> packet) => (byte)(packet[0] >> 4);

        /// <summary>
        /// Builds an IPv4 or IPv6 packet for the family of <paramref name="source"/>, wrapping <paramref name="payload"/>
        /// under protocol/next-header <paramref name="protocol"/>. <paramref name="identification"/> is the IPv4
        /// identification field (ignored for unfragmented IPv6).
        /// </summary>
        public static byte[] Build(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> payload, ushort identification)
            => source.AddressFamily == AddressFamily.InterNetworkV6
                ? Ipv6.Build(source, destination, protocol, payload)
                : Ipv4.Build(source, destination, protocol, payload, identification);

        /// <summary>
        /// Fragments an oversized packet to <paramref name="mtu"/>: IPv4 (RFC 791 §2.3) reads its own identification;
        /// IPv6 (RFC 8200 §4.5) uses <paramref name="identification"/> for the Fragment extension header. Packets that
        /// already fit are returned unchanged (single element).
        /// </summary>
        public static IReadOnlyList<byte[]> Fragment(ReadOnlySpan<byte> packet, int mtu, uint identification)
            => Version(packet) == 6 ? Ipv6.Fragment(packet, mtu, identification) : Ipv4.Fragment(packet, mtu);
    }
}
