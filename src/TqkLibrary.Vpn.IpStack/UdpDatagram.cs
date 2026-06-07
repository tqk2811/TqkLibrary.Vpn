using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>Builds and reads UDP datagrams with the IPv4 pseudo-header checksum (RFC 768).</summary>
    public static class UdpDatagram
    {
        const int HeaderSize = 8;

        /// <summary>Builds a UDP datagram (header + payload) with a computed checksum.</summary>
        public static byte[] Build(IPAddress sourceIp, IPAddress destinationIp, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> payload)
        {
            byte[] datagram = new byte[HeaderSize + payload.Length];
            datagram[0] = (byte)(sourcePort >> 8); datagram[1] = (byte)sourcePort;
            datagram[2] = (byte)(destinationPort >> 8); datagram[3] = (byte)destinationPort;
            datagram[4] = (byte)(datagram.Length >> 8); datagram[5] = (byte)datagram.Length;
            // checksum (6..8) left zero for the computation
            payload.CopyTo(datagram.AsSpan(HeaderSize));

            ushort checksum = Checksum(sourceIp, destinationIp, datagram);
            if (checksum == 0) checksum = 0xFFFF; // a transmitted UDP checksum of 0 means "none"; use the all-ones form
            datagram[6] = (byte)(checksum >> 8);
            datagram[7] = (byte)checksum;
            return datagram;
        }

        /// <summary>Source port.</summary>
        public static ushort SourcePort(ReadOnlySpan<byte> datagram) => (ushort)((datagram[0] << 8) | datagram[1]);

        /// <summary>Destination port.</summary>
        public static ushort DestinationPort(ReadOnlySpan<byte> datagram) => (ushort)((datagram[2] << 8) | datagram[3]);

        /// <summary>The data payload after the 8-byte UDP header.</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> datagram)
        {
            int length = (datagram.Span[4] << 8) | datagram.Span[5];
            if (length < HeaderSize || length > datagram.Length) length = datagram.Length;
            return datagram.Slice(HeaderSize, length - HeaderSize);
        }

        static ushort Checksum(IPAddress sourceIp, IPAddress destinationIp, ReadOnlySpan<byte> datagram)
        {
            uint sum = 0;
            byte[] s = sourceIp.GetAddressBytes();
            byte[] d = destinationIp.GetAddressBytes();
            sum += (uint)((s[0] << 8) | s[1]);
            sum += (uint)((s[2] << 8) | s[3]);
            sum += (uint)((d[0] << 8) | d[1]);
            sum += (uint)((d[2] << 8) | d[3]);
            sum += 17; // protocol (UDP)
            sum += (uint)datagram.Length;
            for (int i = 0; i + 1 < datagram.Length; i += 2)
                sum += (uint)((datagram[i] << 8) | datagram[i + 1]);
            if ((datagram.Length & 1) != 0)
                sum += (uint)(datagram[datagram.Length - 1] << 8);
            return InternetChecksum.Finish(sum);
        }
    }
}
