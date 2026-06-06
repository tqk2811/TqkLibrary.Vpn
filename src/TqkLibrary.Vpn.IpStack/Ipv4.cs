using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>Builds and reads minimal IPv4 packets (no options) for the userspace stack.</summary>
    public static class Ipv4
    {
        /// <summary>IP protocol numbers used by the stack.</summary>
        public const byte ProtocolTcp = 6;

        /// <summary>UDP protocol number.</summary>
        public const byte ProtocolUdp = 17;

        /// <summary>ICMP protocol number.</summary>
        public const byte ProtocolIcmp = 1;

        /// <summary>Builds an IPv4 packet (20-byte header, DF set) wrapping <paramref name="payload"/>.</summary>
        public static byte[] Build(IPAddress source, IPAddress destination, byte protocol, ReadOnlySpan<byte> payload, ushort identification)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;       // Version 4, IHL 5
            packet[1] = 0x00;       // DSCP/ECN
            int total = packet.Length;
            packet[2] = (byte)(total >> 8);
            packet[3] = (byte)total;
            packet[4] = (byte)(identification >> 8);
            packet[5] = (byte)identification;
            packet[6] = 0x40;       // Flags: Don't Fragment
            packet[7] = 0x00;       // Fragment offset
            packet[8] = 64;         // TTL
            packet[9] = protocol;
            // checksum (10..12) left zero for the computation
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);

            ushort checksum = InternetChecksum.Compute(packet.AsSpan(0, 20));
            packet[10] = (byte)(checksum >> 8);
            packet[11] = (byte)checksum;

            payload.CopyTo(packet.AsSpan(20));
            return packet;
        }

        /// <summary>Header length in bytes (IHL * 4).</summary>
        public static int HeaderLength(ReadOnlySpan<byte> packet) => (packet[0] & 0x0F) * 4;

        /// <summary>The protocol field.</summary>
        public static byte Protocol(ReadOnlySpan<byte> packet) => packet[9];

        /// <summary>The source address.</summary>
        public static IPAddress Source(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(12, 4).ToArray());

        /// <summary>The destination address.</summary>
        public static IPAddress Destination(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(16, 4).ToArray());

        /// <summary>The payload (after the IP header).</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> packet) => packet.Slice(HeaderLength(packet.Span));
    }
}
