using System;

namespace TqkLibrary.VpnClient.Tinc.Hosts
{
    /// <summary>
    /// tinc's <b>non-standard</b> Base64 codec (<c>utils.c</c> <c>b64encode</c>/<c>b64decode</c>). It uses the
    /// standard RFC 4648 alphabet (<c>A–Za–z0–9+/</c>) but packs each 3-byte group into its 4 characters in
    /// <b>little-endian</b> order: <c>triplet = b0 | b1&lt;&lt;8 | b2&lt;&lt;16</c>, emitting the lowest 6 bits first.
    /// RFC 4648 instead packs big-endian (<c>b0&lt;&lt;16 | b1&lt;&lt;8 | b2</c>), so <see cref="Convert.ToBase64String"/>
    /// and tinc disagree byte-for-byte on the same input — using the BCL codec for an <c>Ed25519PublicKey</c> makes
    /// tinc decode a different key and the SPTPS SIG fails to verify (found live against tincd 1.1pre18). Output is
    /// always unpadded, matching tinc's host files. Pure/stateless, so static methods are appropriate.
    /// </summary>
    public static class TincBase64
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        static readonly int[] DecodeTable = BuildDecodeTable();

        static int[] BuildDecodeTable()
        {
            var table = new int[256];
            for (int i = 0; i < 256; i++) table[i] = 0;
            for (int i = 0; i < Alphabet.Length; i++) table[Alphabet[i]] = i;
            return table;
        }

        /// <summary>Encodes bytes to tinc's unpadded little-endian Base64 (matches <c>b64encode</c>).</summary>
        public static string Encode(ReadOnlySpan<byte> data)
        {
            int n = data.Length;
            int full = n / 3;
            int rem = n % 3;
            int outLen = full * 4 + (rem == 0 ? 0 : rem + 1);
            var chars = new char[outLen];

            int si = 0, di = 0;
            for (int g = 0; g < full; g++)
            {
                uint triplet = (uint)(data[si] | (data[si + 1] << 8) | (data[si + 2] << 16));
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)];
                si += 3;
            }
            if (rem == 2)
            {
                uint triplet = (uint)(data[si] | (data[si + 1] << 8));
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)];
            }
            else if (rem == 1)
            {
                uint triplet = data[si];
                chars[di++] = Alphabet[(int)(triplet & 63)]; triplet >>= 6;
                chars[di++] = Alphabet[(int)(triplet & 63)];
            }
            return new string(chars);
        }

        /// <summary>Decodes tinc's little-endian Base64 (matches <c>b64decode</c>); ignores any trailing '=' padding.</summary>
        public static byte[] Decode(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            // tinc's b64decode stops at the first NUL/'='; mirror by trimming padding and whitespace.
            int len = text.Length;
            while (len > 0 && (text[len - 1] == '=' || text[len - 1] == '\r' || text[len - 1] == '\n')) len--;

            int outLen = len / 4 * 3 + ((len & 3) == 3 ? 2 : (len & 3) == 2 ? 1 : 0);
            var output = new byte[outLen];

            uint triplet = 0;
            int oi = 0;
            int i = 0;
            for (; i < len; i++)
            {
                triplet |= (uint)DecodeTable[text[i] & 0xff] << (6 * (i & 3));
                if ((i & 3) == 3)
                {
                    output[oi++] = (byte)(triplet & 0xff); triplet >>= 8;
                    output[oi++] = (byte)(triplet & 0xff); triplet >>= 8;
                    output[oi++] = (byte)(triplet & 0xff);
                    triplet = 0;
                }
            }
            if ((i & 3) == 3)
            {
                output[oi++] = (byte)(triplet & 0xff); triplet >>= 8;
                output[oi++] = (byte)(triplet & 0xff);
            }
            else if ((i & 3) == 2)
            {
                output[oi++] = (byte)(triplet & 0xff);
            }
            return output;
        }
    }
}
