using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// The n2n v3 block-Pearson hash used for header-encryption key derivation and the header checksum. n2n does
    /// <b>not</b> use a classic 256-byte Pearson substitution table; it digests the input through a per-round mix
    /// (Stafford's Mix13 bit-finalizer) — a "block Pearson" scheme. This is interop-critical and matches
    /// <c>pearson.c</c> byte-exact (verified against n2n's own <c>tests-hashing</c> golden vectors — see
    /// <c>PearsonHashTests</c>).
    /// <para>
    /// Algorithm: the input is digested 8 bytes at a time as a <b>little-endian</b> 64-bit word, then the remaining
    /// bytes one at a time; before the leftover bytes and before the final length round the running hash word is
    /// bitwise-inverted (<c>~</c>). Each round is <c>h ^= word; h -= part; mix13(h)</c> where <c>part</c> is the lane
    /// index (1 for the 64-bit lane, 2 for the second 128-bit lane). The 128-bit output is two big-endian 64-bit words
    /// (<c>out[0..7] = hash2</c>, <c>out[8..15] = hash1</c>) so the low 8 bytes equal <see cref="Hash64"/>.
    /// </para>
    /// </summary>
    public static class PearsonHash
    {
        // Stafford Mix13 finalizer (the permute64 macro in pearson.c).
        static ulong Mix13(ulong x)
        {
            x ^= x >> 30;
            x *= 0xbf58476d1ce4e5b9UL;
            x ^= x >> 27;
            x *= 0x94d049bb133111ebUL;
            x ^= x >> 31;
            return x;
        }

        // hash_round: h ^= in; h -= dec; mix13(h).  dec = lane index (1, 2, ...).
        static ulong Round(ulong hash, ulong input, ulong dec) => Mix13((hash ^ input) - dec);

        /// <summary>Computes the 64-bit n2n Pearson hash (single lane) of <paramref name="data"/>.</summary>
        public static ulong Hash64(ReadOnlySpan<byte> data)
        {
            ulong orgLen = (ulong)data.Length;
            ulong hash1 = 0;

            int off = 0;
            int len = data.Length;
            while (len > 7)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(off, 8));
                hash1 = Round(hash1, word, 1);
                off += 8; len -= 8;
            }

            hash1 = ~hash1;
            while (len > 0)
            {
                hash1 = Round(hash1, data[off], 1);
                off++; len--;
            }

            hash1 = ~hash1;
            hash1 = Round(hash1, orgLen, 1);
            return hash1;
        }

        /// <summary>
        /// Computes the 128-bit n2n Pearson hash of <paramref name="data"/> into <paramref name="output"/> (16 bytes).
        /// </summary>
        public static void Hash128(ReadOnlySpan<byte> data, Span<byte> output)
        {
            if (output.Length < 16) throw new ArgumentException("output must be at least 16 bytes.", nameof(output));
            ulong orgLen = (ulong)data.Length;
            ulong hash1 = 0, hash2 = 0;

            int off = 0;
            int len = data.Length;
            while (len > 7)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(off, 8));
                hash1 = Round(hash1, word, 1);
                hash2 = Round(hash2, word, 2);
                off += 8; len -= 8;
            }

            hash1 = ~hash1; hash2 = ~hash2;
            while (len > 0)
            {
                byte b = data[off];
                hash1 = Round(hash1, b, 1);
                hash2 = Round(hash2, b, 2);
                off++; len--;
            }

            hash1 = ~hash1; hash2 = ~hash2;
            hash1 = Round(hash1, orgLen, 1);
            hash2 = Round(hash2, orgLen, 2);

            // Stored big-endian: out[0..7] = hash2, out[8..15] = hash1 (so the low half equals Hash64).
            BinaryPrimitives.WriteUInt64BigEndian(output.Slice(0, 8), hash2);
            BinaryPrimitives.WriteUInt64BigEndian(output.Slice(8, 8), hash1);
        }

        /// <summary>Allocating convenience for <see cref="Hash128(ReadOnlySpan{byte}, Span{byte})"/>.</summary>
        public static byte[] Hash128(ReadOnlySpan<byte> data)
        {
            byte[] o = new byte[16];
            Hash128(data, o);
            return o;
        }
    }
}
