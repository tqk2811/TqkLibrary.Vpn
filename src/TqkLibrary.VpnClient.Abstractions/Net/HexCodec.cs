using System;

namespace TqkLibrary.VpnClient.Abstractions.Net
{
    /// <summary>
    /// Hex string ↔ byte[] codec, shared so protocol codecs do not each re-roll the parse loop.
    /// <see cref="Decode"/> throws on malformed input; <see cref="TryDecode"/> reports it via the return value.
    /// </summary>
    public static class HexCodec
    {
        /// <summary>
        /// Decodes a hex string to bytes. Throws <see cref="FormatException"/> when the length is odd or a
        /// non-hex character is present. Accepts upper- or lower-case digits.
        /// </summary>
        public static byte[] Decode(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            if ((hex.Length & 1) != 0) throw new FormatException("Hex string has an odd digit count.");
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                int hi = Nibble(hex[i * 2]);
                int lo = Nibble(hex[i * 2 + 1]);
                if (hi < 0) throw new FormatException($"Invalid hex character '{hex[i * 2]}'.");
                if (lo < 0) throw new FormatException($"Invalid hex character '{hex[i * 2 + 1]}'.");
                result[i] = (byte)((hi << 4) | lo);
            }
            return result;
        }

        /// <summary>
        /// Tries to decode a hex string to bytes. Returns <see langword="false"/> (with <paramref name="result"/>
        /// null) when the length is odd or a non-hex character is present.
        /// </summary>
        public static bool TryDecode(string hex, out byte[]? result)
        {
            result = null;
            if (hex is null || (hex.Length & 1) != 0) return false;
            byte[] buffer = new byte[hex.Length / 2];
            for (int i = 0; i < buffer.Length; i++)
            {
                int hi = Nibble(hex[i * 2]);
                int lo = Nibble(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                buffer[i] = (byte)((hi << 4) | lo);
            }
            result = buffer;
            return true;
        }

        /// <summary>Encodes bytes to a lower-case hex string.</summary>
        public static string Encode(ReadOnlySpan<byte> data)
        {
            const string digits = "0123456789abcdef";
            char[] chars = new char[data.Length * 2];
            for (int i = 0; i < data.Length; i++)
            {
                chars[i * 2] = digits[data[i] >> 4];
                chars[i * 2 + 1] = digits[data[i] & 0xF];
            }
            return new string(chars);
        }

        static int Nibble(char c) => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1,
        };
    }
}
