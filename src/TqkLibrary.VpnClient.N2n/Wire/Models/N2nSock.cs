using System.Buffers.Binary;
using System.Net;

namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// An n2n v3 socket address (<c>n2n_sock_t</c>) as it appears on the wire: a 16-bit family marker
    /// (0x0000 = IPv4, high bit 0x8000 = IPv6), a 16-bit big-endian port, then the 4-byte (IPv4) or 16-byte (IPv6)
    /// address. So 8 bytes for IPv4, 20 bytes for IPv6. Present in a message only when the
    /// <see cref="Enums.N2nFlags.Socket"/> flag is set.
    /// </summary>
    public sealed class N2nSock
    {
        /// <summary>High bit of the family marker set for IPv6, clear for IPv4.</summary>
        public const ushort Ipv6FamilyMarker = 0x8000;

        /// <summary>Encoded size for an IPv4 socket: 2 (family) + 2 (port) + 4 (addr).</summary>
        public const int Ipv4Size = 8;

        /// <summary>Encoded size for an IPv6 socket: 2 (family) + 2 (port) + 16 (addr).</summary>
        public const int Ipv6Size = 20;

        /// <summary>True if this socket holds an IPv6 address (selects the 16-byte address form).</summary>
        public bool IsIpv6 { get; init; }

        /// <summary>UDP port.</summary>
        public ushort Port { get; init; }

        /// <summary>Raw address bytes — 4 for IPv4, 16 for IPv6.</summary>
        public byte[] Address { get; init; } = Array.Empty<byte>();

        /// <summary>Encoded length on the wire for this socket (<see cref="Ipv4Size"/> or <see cref="Ipv6Size"/>).</summary>
        public int EncodedSize => IsIpv6 ? Ipv6Size : Ipv4Size;

        /// <summary>Builds an <see cref="N2nSock"/> from an <see cref="IPEndPoint"/> (IPv4 or IPv6).</summary>
        public static N2nSock FromEndPoint(IPEndPoint endPoint)
        {
            if (endPoint is null) throw new ArgumentNullException(nameof(endPoint));
            byte[] addr = endPoint.Address.GetAddressBytes();
            return new N2nSock
            {
                IsIpv6 = addr.Length == 16,
                Port = (ushort)endPoint.Port,
                Address = addr,
            };
        }

        /// <summary>Converts this socket back to an <see cref="IPEndPoint"/>.</summary>
        public IPEndPoint ToEndPoint() => new IPEndPoint(new IPAddress(Address), Port);

        /// <summary>Writes this socket to <paramref name="dst"/> and returns the byte count written.</summary>
        public int Write(Span<byte> dst)
        {
            int size = EncodedSize;
            if (dst.Length < size) throw new ArgumentException("destination too small", nameof(dst));
            ushort family = IsIpv6 ? Ipv6FamilyMarker : (ushort)0;
            BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(0, 2), family);
            BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(2, 2), Port);
            int addrLen = IsIpv6 ? 16 : 4;
            Address.AsSpan(0, addrLen).CopyTo(dst.Slice(4, addrLen));
            return size;
        }

        /// <summary>Reads a socket from <paramref name="src"/>, advancing <paramref name="offset"/> past it.</summary>
        public static N2nSock Read(ReadOnlySpan<byte> src, ref int offset)
        {
            ushort family = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(offset, 2));
            ushort port = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(offset + 2, 2));
            bool ipv6 = (family & Ipv6FamilyMarker) != 0;
            int addrLen = ipv6 ? 16 : 4;
            byte[] addr = src.Slice(offset + 4, addrLen).ToArray();
            offset += 4 + addrLen;
            return new N2nSock { IsIpv6 = ipv6, Port = port, Address = addr };
        }
    }
}
