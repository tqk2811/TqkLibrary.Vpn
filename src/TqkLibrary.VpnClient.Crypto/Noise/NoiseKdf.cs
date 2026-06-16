using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// The Noise protocol / WireGuard key-derivation function (HKDF, RFC 5869, with HMAC-BLAKE2s as the PRF).
    /// <c>KDFn(key, input)</c> extracts <c>t0 = HMAC(key, input)</c>, then expands <c>t1 = HMAC(t0, 0x01)</c> and
    /// <c>ti = HMAC(t0, t(i-1) || i)</c>, returning the first <c>n</c> 32-byte blocks (n = 1, 2 or 3 in WireGuard).
    /// Differs from <see cref="PrfPlus"/> (IKEv2 prf+): prf+ chains the original seed every block, KDF chains t0.
    /// </summary>
    public static class NoiseKdf
    {
        const int BlockSize = 32; // HMAC-BLAKE2s output size

        /// <summary>
        /// Derives <paramref name="outputs"/> chained 32-byte blocks. <paramref name="prf"/> must be HMAC-BLAKE2s
        /// (<see cref="HmacBlake2sPrf"/>); its <see cref="IPrf.OutputSizeInBytes"/> must be 32.
        /// </summary>
        public static byte[][] Derive(IPrf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, int outputs)
        {
            if (outputs < 1 || outputs > 255) throw new ArgumentOutOfRangeException(nameof(outputs));
            if (prf.OutputSizeInBytes != BlockSize)
                throw new ArgumentException("NoiseKdf requires a 32-byte PRF (HMAC-BLAKE2s).", nameof(prf));

            byte[] t0 = new byte[BlockSize];
            prf.Compute(key, input, t0); // HKDF-Extract

            var result = new byte[outputs][];
            byte[] previous = Array.Empty<byte>();
            for (int i = 1; i <= outputs; i++)
            {
                // HKDF-Expand block: HMAC(t0, T(i-1) | i)
                byte[] seed = new byte[previous.Length + 1];
                Buffer.BlockCopy(previous, 0, seed, 0, previous.Length);
                seed[seed.Length - 1] = (byte)i;

                byte[] ti = new byte[BlockSize];
                prf.Compute(t0, seed, ti);
                result[i - 1] = ti;
                previous = ti;
            }
            return result;
        }

        /// <summary>KDF1 — one output (e.g. Noise MixKey chain-key advance).</summary>
        public static byte[] Kdf1(IPrf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
            => Derive(prf, key, input, 1)[0];

        /// <summary>KDF2 — two outputs (e.g. chain key + message/cipher key).</summary>
        public static (byte[] T1, byte[] T2) Kdf2(IPrf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        {
            byte[][] t = Derive(prf, key, input, 2);
            return (t[0], t[1]);
        }

        /// <summary>KDF3 — three outputs (e.g. chain key + hash-mix value + cipher key, used when mixing the PSK).</summary>
        public static (byte[] T1, byte[] T2, byte[] T3) Kdf3(IPrf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        {
            byte[][] t = Derive(prf, key, input, 3);
            return (t[0], t[1], t[2]);
        }
    }
}
