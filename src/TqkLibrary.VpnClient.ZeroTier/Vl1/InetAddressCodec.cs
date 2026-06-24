using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Serialises and parses ZeroTier's <c>InetAddress::serialize</c> form: a one-byte type tag (<c>0x00</c> nil,
    /// <c>0x04</c> IPv4, <c>0x06</c> IPv6) then, for a non-nil address, the raw network-order address bytes followed by a
    /// 2-byte big-endian port. The type tag lets a parser self-describe its length, so a run of InetAddresses (static IP
    /// list, routes) can be read back-to-back; <see cref="TryDecode"/> reports how many bytes it consumed.
    /// </summary>
    public sealed class InetAddressCodec
    {
        const byte TagNil = 0x00;
        const byte TagIpv4 = 0x04;
        const byte TagIpv6 = 0x06;

        /// <summary>The encoded length of <paramref name="value"/> (1 for nil, 7 for IPv4, 19 for IPv6).</summary>
        public int EncodedLength(InetAddressValue value)
        {
            if (value is null || value.IsNil) return 1;
            return value.Address!.AddressFamily == AddressFamily.InterNetworkV6 ? 1 + 16 + 2 : 1 + 4 + 2;
        }

        /// <summary>Serialises an InetAddress (nil produces a single 0x00 byte).</summary>
        public byte[] Encode(InetAddressValue value)
        {
            if (value is null || value.IsNil) return new byte[] { TagNil };
            byte[] addr = value.Address!.GetAddressBytes();
            bool v6 = value.Address.AddressFamily == AddressFamily.InterNetworkV6;
            byte[] outp = new byte[1 + addr.Length + 2];
            outp[0] = v6 ? TagIpv6 : TagIpv4;
            addr.CopyTo(outp, 1);
            BinaryPrimitives.WriteUInt16BigEndian(outp.AsSpan(1 + addr.Length, 2), value.Port);
            return outp;
        }

        /// <summary>
        /// Parses one InetAddress from the front of <paramref name="source"/>. Returns false on a truncated buffer or an
        /// unsupported type tag; on success <paramref name="consumed"/> is the number of bytes read (so the caller can
        /// advance through a packed list).
        /// </summary>
        public bool TryDecode(ReadOnlySpan<byte> source, out InetAddressValue value, out int consumed)
        {
            value = InetAddressValue.Nil;
            consumed = 0;
            if (source.Length < 1) return false;

            byte tag = source[0];
            switch (tag)
            {
                case TagNil:
                    value = InetAddressValue.Nil;
                    consumed = 1;
                    return true;
                case TagIpv4:
                    if (source.Length < 1 + 4 + 2) return false;
                    value = new InetAddressValue
                    {
                        Address = new IPAddress(source.Slice(1, 4).ToArray()),
                        Port = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(1 + 4, 2)),
                    };
                    consumed = 1 + 4 + 2;
                    return true;
                case TagIpv6:
                    if (source.Length < 1 + 16 + 2) return false;
                    value = new InetAddressValue
                    {
                        Address = new IPAddress(source.Slice(1, 16).ToArray()),
                        Port = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(1 + 16, 2)),
                    };
                    consumed = 1 + 16 + 2;
                    return true;
                default:
                    return false;
            }
        }
    }
}
