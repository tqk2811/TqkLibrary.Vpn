using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Alias the specific BouncyCastle digest (see Curve25519DhGroup for why we never import the namespace wholesale).
using Blake2sDigest = Org.BouncyCastle.Crypto.Digests.Blake2sDigest;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// BLAKE2s-256 (RFC 7693) one-shot hash exposed as an <see cref="IHashAlgo"/> (32-byte digest, unkeyed). The
    /// Noise protocol / WireGuard uses it for the running transcript hash and as the inner hash of HMAC
    /// (<see cref="HmacBlake2sPrf"/>). No native BLAKE2s exists in either TFM's BCL → BouncyCastle on both.
    /// </summary>
    public sealed class Blake2s : IHashAlgo
    {
        const int DigestBits = 256; // Blake2sDigest(int) takes the size in BITS

        /// <inheritdoc/>
        public int HashSizeInBytes => DigestBits / 8;

        /// <inheritdoc/>
        public void ComputeHash(ReadOnlySpan<byte> input, Span<byte> destination)
        {
            var digest = new Blake2sDigest(DigestBits);
            byte[] data = input.ToArray();
            digest.BlockUpdate(data, 0, data.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            output.AsSpan(0, HashSizeInBytes).CopyTo(destination);
        }
    }
}
