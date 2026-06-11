namespace TqkLibrary.Vpn.Ethernet
{
    /// <summary>
    /// Builds and reads Ethernet II frames (dst MAC | src MAC | EtherType | payload) for the userspace L2 fabric.
    /// Minimal on purpose — no 802.1Q VLAN tag, no FCS (the NIC/driver adds it), no min-60-byte padding (a software
    /// switch needs none). Mirrors the codec style of <c>TqkLibrary.Vpn.IpStack.Ipv4</c>.
    /// </summary>
    public static class EthernetFrame
    {
        /// <summary>Ethernet II header length in bytes (6 dst + 6 src + 2 EtherType).</summary>
        public const int HeaderLength = 14;

        /// <summary>EtherType for IPv4 payloads.</summary>
        public const ushort EtherTypeIpv4 = 0x0800;

        /// <summary>EtherType for IPv6 payloads.</summary>
        public const ushort EtherTypeIpv6 = 0x86DD;

        /// <summary>EtherType for ARP payloads.</summary>
        public const ushort EtherTypeArp = 0x0806;

        /// <summary>Builds an Ethernet II frame (14-byte header) wrapping <paramref name="payload"/>.</summary>
        public static byte[] Build(MacAddress destination, MacAddress source, ushort etherType, ReadOnlySpan<byte> payload)
        {
            byte[] frame = new byte[HeaderLength + payload.Length];
            destination.CopyTo(frame.AsSpan(0, MacAddress.Size));
            source.CopyTo(frame.AsSpan(MacAddress.Size, MacAddress.Size));
            frame[12] = (byte)(etherType >> 8);
            frame[13] = (byte)etherType;
            payload.CopyTo(frame.AsSpan(HeaderLength));
            return frame;
        }

        /// <summary>The destination MAC (first 6 bytes).</summary>
        public static MacAddress Destination(ReadOnlySpan<byte> frame) => MacAddress.FromBytes(frame.Slice(0, MacAddress.Size));

        /// <summary>The source MAC (bytes 6..11).</summary>
        public static MacAddress Source(ReadOnlySpan<byte> frame) => MacAddress.FromBytes(frame.Slice(MacAddress.Size, MacAddress.Size));

        /// <summary>The 16-bit EtherType field (bytes 12..13).</summary>
        public static ushort EtherType(ReadOnlySpan<byte> frame) => (ushort)((frame[12] << 8) | frame[13]);

        /// <summary>The payload (after the 14-byte header).</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> frame) => frame.Slice(HeaderLength);
    }
}
