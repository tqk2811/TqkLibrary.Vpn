// Alias the specific BouncyCastle digest (see Curve25519DhGroup for why we never import the namespace wholesale).
using Blake2sDigest = Org.BouncyCastle.Crypto.Digests.Blake2sDigest;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// Keyed BLAKE2s (RFC 7693 §2.9 / §4) with a caller-chosen output length — the MAC primitive WireGuard uses for
    /// mac1/mac2 (16-byte output keyed by a 32-byte label hash). Stateless pure function: one call per MAC. This is
    /// BLAKE2s's own keyed mode, distinct from HMAC-over-BLAKE2s (<see cref="HmacBlake2sPrf"/>).
    /// </summary>
    public static class Blake2sKeyedMac
    {
        /// <summary>
        /// Computes keyed BLAKE2s of <paramref name="input"/> under <paramref name="key"/> into
        /// <paramref name="output"/>; the digest length equals <paramref name="output"/>.Length (must be 1..32).
        /// </summary>
        public static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
        {
            int outLen = output.Length;
            if (outLen < 1 || outLen > 32) throw new ArgumentException("BLAKE2s output length must be 1..32 bytes.", nameof(output));
            // Note: this Blake2sDigest overload takes the digest size in BYTES (unlike Blake2sDigest(int) which is bits).
            var digest = new Blake2sDigest(key.ToArray(), outLen, null, null);
            byte[] data = input.ToArray();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            result.AsSpan(0, outLen).CopyTo(output);
        }
    }
}
