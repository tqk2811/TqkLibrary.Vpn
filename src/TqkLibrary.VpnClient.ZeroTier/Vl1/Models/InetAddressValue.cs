using System.Net;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Models
{
    /// <summary>
    /// A ZeroTier serialized <c>InetAddress</c> — an IP endpoint (or the nil address) as it appears on the wire and in
    /// network-config dictionaries. The wire form is a one-byte type discriminator followed, for a non-nil address, by
    /// the raw address bytes and a 2-byte big-endian port: <c>0x00</c> = nil, <c>0x04</c> = IPv4 (addr 4 + port 2),
    /// <c>0x06</c> = IPv6 (addr 16 + port 2). ZeroTier overloads the port field of a static-IP assignment to carry the
    /// subnet prefix length, so <see cref="Port"/> doubles as the CIDR prefix in that context.
    /// </summary>
    public sealed class InetAddressValue
    {
        /// <summary>The nil (empty) InetAddress — a single 0x00 byte on the wire.</summary>
        public static readonly InetAddressValue Nil = new InetAddressValue();

        /// <summary>The IP address, or null for the nil address.</summary>
        public IPAddress? Address { get; set; }

        /// <summary>The port (or, for a static-IP assignment, the subnet prefix length). Zero for nil.</summary>
        public ushort Port { get; set; }

        /// <summary>True if this is the nil (empty) address.</summary>
        public bool IsNil => Address is null;
    }
}
