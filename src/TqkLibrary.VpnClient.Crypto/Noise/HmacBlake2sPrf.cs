using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Alias the specific BouncyCastle types (see Curve25519DhGroup for why we never import the namespace wholesale).
using Blake2sDigest = Org.BouncyCastle.Crypto.Digests.Blake2sDigest;
using HMac = Org.BouncyCastle.Crypto.Macs.HMac;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// HMAC (RFC 2104, 64-byte block) using BLAKE2s-256 as the inner hash — the PRF the Noise protocol / WireGuard
    /// builds its KDF on (see <see cref="NoiseKdf"/>). 32-byte output. This is *standard HMAC over BLAKE2s*, NOT
    /// BLAKE2s's own keyed mode (use <see cref="Blake2sKeyedMac"/> for that). BouncyCastle on both TFMs.
    /// </summary>
    public sealed class HmacBlake2sPrf : IPrf
    {
        /// <inheritdoc/>
        public int OutputSizeInBytes => 32;

        /// <inheritdoc/>
        public void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> seed, Span<byte> output)
        {
            var hmac = new HMac(new Blake2sDigest(256));
            hmac.Init(new KeyParameter(key.ToArray()));
            byte[] data = seed.ToArray();
            hmac.BlockUpdate(data, 0, data.Length);
            byte[] mac = new byte[hmac.GetMacSize()];
            hmac.DoFinal(mac, 0);
            mac.AsSpan(0, OutputSizeInBytes).CopyTo(output);
        }
    }
}
