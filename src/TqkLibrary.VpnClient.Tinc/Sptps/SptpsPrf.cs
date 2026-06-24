using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The SPTPS key-expansion PRF: a TLS-1.2-style <c>P_hash</c> built on HMAC-SHA-512, keyed by the ECDH shared
    /// secret. tinc derives the <c>sptps_key_t</c> (128 bytes) by chaining 64-byte HMAC blocks over the seed
    /// <c>"key expansion" || responder_nonce || initiator_nonce || label</c>.
    /// <para>
    /// Block recurrence (from tinc <c>prf.c</c>): <c>A[0] = HMAC_SHA512(secret, zeroes(64) || seed)</c> and
    /// <c>A[n] = HMAC_SHA512(secret, A[n-1] || seed)</c>; the output is <c>A[1] || A[2] || …</c> (i.e. the very first
    /// HMAC over the all-zero accumulator is consumed only as the chaining seed, never emitted).
    /// </para>
    /// Pure/stateless — no instance state, so a static method is appropriate.
    /// </summary>
    public static class SptpsPrf
    {
        const int BlockSize = 64; // HMAC-SHA-512 output

        /// <summary>
        /// Expands <paramref name="secret"/> over <paramref name="seed"/> into <paramref name="length"/> bytes of key
        /// material following tinc's <c>prf()</c>.
        /// </summary>
        public static byte[] Expand(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            byte[] result = new byte[length];
            if (length == 0) return result;

            using var hmac = new HMACSHA512(secret.ToArray());
            byte[] seedBytes = seed.ToArray();

            // A[0] = HMAC(secret, zeroes(64) || seed) — the accumulator, not emitted.
            byte[] a = Hmac(hmac, new byte[BlockSize], seedBytes);

            int produced = 0;
            while (produced < length)
            {
                // A[n] = HMAC(secret, A[n-1] || seed) — this is the emitted block.
                a = Hmac(hmac, a, seedBytes);
                int take = Math.Min(BlockSize, length - produced);
                Array.Copy(a, 0, result, produced, take);
                produced += take;
            }
            return result;
        }

        static byte[] Hmac(HMACSHA512 hmac, byte[] prefix, byte[] seed)
        {
            byte[] input = new byte[prefix.Length + seed.Length];
            Buffer.BlockCopy(prefix, 0, input, 0, prefix.Length);
            Buffer.BlockCopy(seed, 0, input, prefix.Length, seed.Length);
            return hmac.ComputeHash(input);
        }
    }
}
