using System.Net;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>Builds and reads TCP segments (with the pseudo-header checksum).</summary>
    public static class TcpSegment
    {
        /// <summary>Builds a TCP segment. Pass <paramref name="mss"/> &gt; 0 to include the MSS option (for SYN).</summary>
        public static byte[] Build(
            IPAddress sourceIp, IPAddress destinationIp,
            ushort sourcePort, ushort destinationPort,
            uint sequence, uint acknowledgment, TcpFlags flags, ushort window,
            ReadOnlySpan<byte> payload, ushort mss = 0)
        {
            int headerLength = mss > 0 ? 24 : 20;
            byte[] segment = new byte[headerLength + payload.Length];
            WriteU16(segment, 0, sourcePort);
            WriteU16(segment, 2, destinationPort);
            WriteU32(segment, 4, sequence);
            WriteU32(segment, 8, acknowledgment);
            segment[12] = (byte)((headerLength / 4) << 4); // data offset
            segment[13] = (byte)flags;
            WriteU16(segment, 14, window);
            // checksum (16..18) and urgent (18..20) left zero
            if (mss > 0)
            {
                segment[20] = 2; // MSS option kind
                segment[21] = 4; // length
                WriteU16(segment, 22, mss);
            }
            payload.CopyTo(segment.AsSpan(headerLength));

            ushort checksum = Checksum(sourceIp, destinationIp, segment);
            WriteU16(segment, 16, checksum);
            return segment;
        }

        static ushort Checksum(IPAddress sourceIp, IPAddress destinationIp, ReadOnlySpan<byte> segment)
        {
            uint sum = 0;
            byte[] s = sourceIp.GetAddressBytes();
            byte[] d = destinationIp.GetAddressBytes();
            sum += (uint)((s[0] << 8) | s[1]);
            sum += (uint)((s[2] << 8) | s[3]);
            sum += (uint)((d[0] << 8) | d[1]);
            sum += (uint)((d[2] << 8) | d[3]);
            sum += 6; // protocol (TCP)
            sum += (uint)segment.Length;
            for (int i = 0; i + 1 < segment.Length; i += 2)
                sum += (uint)((segment[i] << 8) | segment[i + 1]);
            if ((segment.Length & 1) != 0)
                sum += (uint)(segment[segment.Length - 1] << 8);
            return InternetChecksum.Finish(sum);
        }

        /// <summary>Source port.</summary>
        public static ushort SourcePort(ReadOnlySpan<byte> s) => (ushort)((s[0] << 8) | s[1]);

        /// <summary>Destination port.</summary>
        public static ushort DestinationPort(ReadOnlySpan<byte> s) => (ushort)((s[2] << 8) | s[3]);

        /// <summary>Sequence number.</summary>
        public static uint Sequence(ReadOnlySpan<byte> s) => ReadU32(s, 4);

        /// <summary>Acknowledgment number.</summary>
        public static uint Acknowledgment(ReadOnlySpan<byte> s) => ReadU32(s, 8);

        /// <summary>Header length in bytes (data offset * 4).</summary>
        public static int DataOffset(ReadOnlySpan<byte> s) => (s[12] >> 4) * 4;

        /// <summary>Control flags.</summary>
        public static TcpFlags Flags(ReadOnlySpan<byte> s) => (TcpFlags)s[13];

        /// <summary>Advertised window.</summary>
        public static ushort Window(ReadOnlySpan<byte> s) => (ushort)((s[14] << 8) | s[15]);

        /// <summary>The data payload after the TCP header.</summary>
        public static ReadOnlyMemory<byte> Payload(ReadOnlyMemory<byte> segment) => segment.Slice(DataOffset(segment.Span));

        static void WriteU16(byte[] b, int o, ushort v) { b[o] = (byte)(v >> 8); b[o + 1] = (byte)v; }
        static void WriteU32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        static uint ReadU32(ReadOnlySpan<byte> b, int o) => ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];
    }
}
