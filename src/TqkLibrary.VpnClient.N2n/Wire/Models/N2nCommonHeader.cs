using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.N2n.Wire.Enums;

namespace TqkLibrary.VpnClient.N2n.Wire.Models
{
    /// <summary>
    /// The n2n v3 common header (<c>n2n_common_t</c>) that prefixes every message — 24 bytes:
    /// <c>version(1) ‖ ttl(1) ‖ flags(2, big-endian) ‖ community(20, null-padded)</c>. The 16-bit <c>flags</c> field
    /// packs the <see cref="N2nPacketType"/> in its low 5 bits (<see cref="N2nFlags.TypeMask"/>) and the
    /// <see cref="N2nFlags"/> bits above. This is the cleartext header used when n2n header-encryption is disabled
    /// (supernode/edge run with <c>-H</c> off); the encrypted-header framing (Speck) is intentionally not implemented.
    /// </summary>
    public sealed class N2nCommonHeader
    {
        /// <summary>Protocol version byte (defaults to <see cref="N2nConstants.PktVersion"/> = 3).</summary>
        public byte Version { get; init; } = N2nConstants.PktVersion;

        /// <summary>Time-to-live for relays (defaults to <see cref="N2nConstants.DefaultTtl"/>).</summary>
        public byte Ttl { get; init; } = N2nConstants.DefaultTtl;

        /// <summary>The message type, packed into the low 5 bits of the flags field.</summary>
        public N2nPacketType PacketType { get; init; }

        /// <summary>The flag bits (excluding the type field) — direction / socket-present / options.</summary>
        public N2nFlags Flags { get; init; }

        /// <summary>Community name (≤ 20 ASCII bytes; null-padded on the wire).</summary>
        public string Community { get; init; } = string.Empty;

        /// <summary>Writes the 24-byte header to <paramref name="dst"/> and returns the byte count written.</summary>
        public int Write(Span<byte> dst)
        {
            if (dst.Length < N2nConstants.CommonHeaderSize) throw new ArgumentException("destination too small", nameof(dst));
            dst[0] = Version;
            dst[1] = Ttl;
            ushort flags = (ushort)(((ushort)Flags & ~(ushort)N2nFlags.TypeMask) | ((byte)PacketType & (ushort)N2nFlags.TypeMask));
            BinaryPrimitives.WriteUInt16BigEndian(dst.Slice(2, 2), flags);
            WriteCommunity(Community, dst.Slice(4, N2nConstants.CommunitySize));
            return N2nConstants.CommonHeaderSize;
        }

        /// <summary>Reads a 24-byte common header from <paramref name="src"/>, advancing <paramref name="offset"/> past it.</summary>
        public static N2nCommonHeader Read(ReadOnlySpan<byte> src, ref int offset)
        {
            byte version = src[offset];
            byte ttl = src[offset + 1];
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(offset + 2, 2));
            string community = ReadCommunity(src.Slice(offset + 4, N2nConstants.CommunitySize));
            offset += N2nConstants.CommonHeaderSize;
            return new N2nCommonHeader
            {
                Version = version,
                Ttl = ttl,
                PacketType = (N2nPacketType)(flags & (ushort)N2nFlags.TypeMask),
                Flags = (N2nFlags)(flags & ~(ushort)N2nFlags.TypeMask),
                Community = community,
            };
        }

        static void WriteCommunity(string community, Span<byte> dst)
        {
            dst.Clear();
            byte[] bytes = Encoding.ASCII.GetBytes(community);
            int n = Math.Min(bytes.Length, N2nConstants.CommunitySize);
            bytes.AsSpan(0, n).CopyTo(dst);
        }

        static string ReadCommunity(ReadOnlySpan<byte> src)
        {
            int len = src.IndexOf((byte)0);
            if (len < 0) len = src.Length;
            return Encoding.ASCII.GetString(src.Slice(0, len).ToArray());
        }
    }
}
