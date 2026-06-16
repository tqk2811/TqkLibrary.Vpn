using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// SHA-0 message digest (FIPS 180, 1993) — the original Secure Hash Algorithm, identical to SHA-1
    /// (FIPS 180-1) <b>except</b> the message schedule has <b>no left-rotate by 1</b>:
    /// <c>W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]</c> (SHA-1 wraps that in <c>ROTL1(...)</c>).
    /// Not part of the BCL; needed for the SoftEther SSL-VPN password authentication
    /// (hash of password+username, computed locally — the hash itself never crosses the wire).
    /// Cryptographically broken — used only because the protocol mandates it.
    /// </summary>
    public sealed class Sha0 : IHashAlgo
    {
        /// <inheritdoc/>
        public int HashSizeInBytes => 20;

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            if (destination.Length < 20) throw new ArgumentException("destination must be >= 20 bytes", nameof(destination));

            uint h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;

            // Process full 64-byte blocks, then a padded tail (0x80 marker + big-endian 64-bit bit length).
            int fullBlocks = input.Length / 64;
            for (int i = 0; i < fullBlocks; i++)
                ProcessBlock(input.Slice(i * 64, 64), ref h0, ref h1, ref h2, ref h3, ref h4);

            ReadOnlySpan<byte> tail = input.Slice(fullBlocks * 64);
            Span<byte> buffer = stackalloc byte[128];
            tail.CopyTo(buffer);
            buffer[tail.Length] = 0x80;
            int padded = (tail.Length < 56) ? 64 : 128;
            ulong bitLength = (ulong)input.Length * 8;
            WriteUInt64BigEndian(buffer.Slice(padded - 8), bitLength);

            ProcessBlock(buffer.Slice(0, 64), ref h0, ref h1, ref h2, ref h3, ref h4);
            if (padded == 128)
                ProcessBlock(buffer.Slice(64, 64), ref h0, ref h1, ref h2, ref h3, ref h4);

            WriteUInt32BigEndian(destination, h0);
            WriteUInt32BigEndian(destination.Slice(4), h1);
            WriteUInt32BigEndian(destination.Slice(8), h2);
            WriteUInt32BigEndian(destination.Slice(12), h3);
            WriteUInt32BigEndian(destination.Slice(16), h4);
        }

        /// <summary>Convenience one-shot that allocates a 20-byte result.</summary>
        public static byte[] Hash(ReadOnlySpan<byte> input)
        {
            var result = new byte[20];
            new Sha0().ComputeHash(input, result);
            return result;
        }

        static void ProcessBlock(ReadOnlySpan<byte> block, ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4)
        {
            Span<uint> w = stackalloc uint[80];
            for (int i = 0; i < 16; i++)
                w[i] = (uint)((block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]);
            // SHA-0 message schedule: NO ROTL1 here (the single difference from SHA-1).
            for (int i = 16; i < 80; i++)
                w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];

            uint a = h0, b = h1, c = h2, d = h3, e = h4;
            for (int i = 0; i < 80; i++)
            {
                uint f, k;
                if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999u; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
                else { f = b ^ c ^ d; k = 0xca62c1d6u; }

                uint temp = Rotl(a, 5) + f + e + k + w[i];
                e = d; d = c; c = Rotl(b, 30); b = a; a = temp;
            }

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        }

        static uint Rotl(uint v, int s) => (v << s) | (v >> (32 - s));

        static void WriteUInt32BigEndian(Span<byte> dst, uint v)
        {
            dst[0] = (byte)(v >> 24);
            dst[1] = (byte)(v >> 16);
            dst[2] = (byte)(v >> 8);
            dst[3] = (byte)v;
        }

        static void WriteUInt64BigEndian(Span<byte> dst, ulong v)
        {
            for (int i = 0; i < 8; i++) dst[i] = (byte)(v >> (56 - 8 * i));
        }
    }
}
