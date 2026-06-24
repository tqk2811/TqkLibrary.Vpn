using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The SPTPS key-expansion PRF: the <b>TLS-1.0-style P_hash with XOR folding</b> built on HMAC-SHA-512, keyed by
    /// the ECDH shared secret (tinc <c>prf.c</c> <c>prf_xor</c>). It is <b>not</b> the simpler TLS-1.2 P_hash — each
    /// output block is the XOR of an "outer" HMAC, and the accumulator advances with a separate "inner" HMAC:
    /// <para>
    /// With <c>len = 64</c> (SHA-512), <c>A[0] = zeroes(64)</c>; for each block <c>n ≥ 1</c>:
    /// <c>A[n] = HMAC(secret, A[n-1] || seed)</c> (inner) and <c>block = HMAC(secret, A[n] || seed)</c> (outer); the
    /// output (pre-zeroed) is XOR-folded with each <c>block</c>. The seed is
    /// <c>"key expansion" || initiator_nonce || responder_nonce || label</c>. Two HMACs per block — a single
    /// (copy-not-xor, one-HMAC) chain produces different key material and the record cipher fails to interoperate
    /// (found live against tincd 1.1pre18; self-pair offline could not catch it because both ends shared the codec).
    /// </para>
    /// Pure/stateless — no instance state, so a static method is appropriate.
    /// </summary>
    public static class SptpsPrf
    {
        const int BlockSize = 64; // HMAC-SHA-512 output

        /// <summary>
        /// Expands <paramref name="secret"/> over <paramref name="seed"/> into <paramref name="length"/> bytes of key
        /// material following tinc's <c>prf_xor()</c> (TLS-1.0 P_hash, XOR-folded, HMAC-SHA-512).
        /// </summary>
        public static byte[] Expand(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> seed, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            byte[] result = new byte[length]; // pre-zeroed, then XOR-folded (matches prf()'s memset + prf_xor)
            if (length == 0) return result;

            using var hmac = new HMACSHA512(secret.ToArray());
            byte[] seedBytes = seed.ToArray();

            // accumulator A = zeroes(64) initially; the inner/outer HMACs both run over (A || seed).
            byte[] a = new byte[BlockSize];

            int produced = 0;
            while (produced < length)
            {
                // Inner HMAC advances the accumulator: A[n] = HMAC(secret, A[n-1] || seed).
                a = Hmac(hmac, a, seedBytes);
                // Outer HMAC produces the key block: HMAC(secret, A[n] || seed).
                byte[] block = Hmac(hmac, a, seedBytes);
                int take = Math.Min(BlockSize, length - produced);
                for (int i = 0; i < take; i++) result[produced + i] ^= block[i];
                produced += take;
            }
            return result;
        }

        static byte[] Hmac(HMACSHA512 hmac, byte[] accumulator, byte[] seed)
        {
            byte[] input = new byte[accumulator.Length + seed.Length];
            Buffer.BlockCopy(accumulator, 0, input, 0, accumulator.Length);
            Buffer.BlockCopy(seed, 0, input, accumulator.Length, seed.Length);
            return hmac.ComputeHash(input);
        }
    }
}
