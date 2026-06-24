using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// n2n v3 device IP subnet (<c>n2n_ip_subnet_t</c>): a 32-bit big-endian network address and a 1-byte prefix
    /// length — 5 bytes on the wire. Edges send <see cref="Unset"/> (all zeros, bitlen 0) when they let the supernode
    /// assign an address.
    /// </summary>
    public readonly struct N2nIpSubnet
    {
        /// <summary>Encoded length: 4 (net_addr) + 1 (net_bitlen).</summary>
        public const int Size = 5;

        /// <summary>Network address (host order; written big-endian).</summary>
        public uint NetAddr { get; }

        /// <summary>Prefix length in bits.</summary>
        public byte NetBitLen { get; }

        /// <summary>Creates a subnet from a network address and prefix length.</summary>
        public N2nIpSubnet(uint netAddr, byte netBitLen)
        {
            NetAddr = netAddr;
            NetBitLen = netBitLen;
        }

        /// <summary>The "let the supernode assign" sentinel: address 0, prefix 0.</summary>
        public static N2nIpSubnet Unset => new N2nIpSubnet(0, 0);

        /// <summary>Writes this subnet to <paramref name="dst"/> and returns the byte count written.</summary>
        public int Write(Span<byte> dst)
        {
            BinaryPrimitives.WriteUInt32BigEndian(dst.Slice(0, 4), NetAddr);
            dst[4] = NetBitLen;
            return Size;
        }

        /// <summary>Reads a subnet from <paramref name="src"/>, advancing <paramref name="offset"/> past it.</summary>
        public static N2nIpSubnet Read(ReadOnlySpan<byte> src, ref int offset)
        {
            uint addr = BinaryPrimitives.ReadUInt32BigEndian(src.Slice(offset, 4));
            byte bitlen = src[offset + 4];
            offset += Size;
            return new N2nIpSubnet(addr, bitlen);
        }
    }
}
