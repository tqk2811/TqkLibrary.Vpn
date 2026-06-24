using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Derives the long-lived symmetric key shared between two ZeroTier nodes from their Curve25519 identities. Each
    /// node runs X25519 between its own Curve25519 private key and the peer's Curve25519 public key; the 32-byte raw
    /// agreement is then expanded with SHA-512 to a 64-byte key, of which the first 32 bytes seed the per-packet
    /// Salsa20 cipher. (The full 64 bytes are retained so future suites that need more key material can use them.)
    /// <para>
    /// This is symmetric: both ends compute the identical secret. The per-packet nonce and the one-time Poly1305 key
    /// come from the packet ID and the Salsa20 key-stream — see <c>Vl1PacketCodec</c>.
    /// </para>
    /// </summary>
    public sealed class Vl1KeyDerivation
    {
        readonly Curve25519DhGroup _dh = new Curve25519DhGroup();

        /// <summary>Length of the derived key material.</summary>
        public const int KeySize = 64;

        /// <summary>
        /// Computes the 64-byte shared key between <paramref name="myCurve25519Private"/> and
        /// <paramref name="peerCurve25519Public"/> (both 32 bytes). The first 32 bytes are the Salsa20 key.
        /// </summary>
        public byte[] DeriveSharedKey(ReadOnlySpan<byte> myCurve25519Private, ReadOnlySpan<byte> peerCurve25519Public)
        {
            byte[] shared = _dh.DeriveSharedSecret(myCurve25519Private, peerCurve25519Public); // 32 bytes
            byte[] key = Sha512(shared);
            Array.Clear(shared, 0, shared.Length); // best-effort wipe of the raw agreement
            return key; // 64 bytes; key[0..32] = Salsa20 key
        }

        static byte[] Sha512(ReadOnlySpan<byte> input)
        {
#if NET5_0_OR_GREATER
            byte[] digest = new byte[64];
            SHA512.HashData(input, digest);
            return digest;
#else
            using var sha = SHA512.Create();
            return sha.ComputeHash(input.ToArray());
#endif
        }
    }
}
