using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Alias the one BouncyCastle type rather than importing Org.BouncyCastle.* wholesale (its Crypto namespace
// defines an IAeadCipher that would clash with this project's interface — see Aead/*.cs). Neither TFM's BCL
// ships X25519, so BouncyCastle is used on net8.0 and netstandard2.0 alike (no #if split, unlike Aead/).
using X25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// Curve25519 (X25519, RFC 7748) Diffie-Hellman exposed as an <see cref="IDhGroup"/> — IANA group 31 (RFC 8031),
    /// 32-byte private and public values. X25519 clamps the scalar internally (RFC 7748 §5), so any 32 random bytes
    /// form a valid private key. Foundation for the Noise protocol / WireGuard (V.3) and reusable for Nebula (V.7).
    /// </summary>
    public sealed class Curve25519DhGroup : IDhGroup
    {
        const int KeySize = 32; // X25519.ScalarSize == X25519.PointSize == 32

        static Curve25519DhGroup()
        {
            // ScalarMultBase reads a precomputed base-point table; build it once before first use.
            X25519.Precompute();
        }

        /// <inheritdoc/>
        public int GroupId => 31;

        /// <inheritdoc/>
        public int PublicValueSizeInBytes => KeySize;

        /// <inheritdoc/>
        public byte[] GeneratePrivateKey()
        {
            byte[] priv = new byte[KeySize];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(priv);
            return priv; // clamping happens at scalar-mult time, so no post-processing is needed
        }

        /// <inheritdoc/>
        public byte[] DerivePublicValue(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != KeySize) throw new ArgumentException($"X25519 private key must be {KeySize} bytes.", nameof(privateKey));
            byte[] k = privateKey.ToArray();
            byte[] pub = new byte[KeySize];
            X25519.ScalarMultBase(k, 0, pub, 0);
            return pub;
        }

        /// <inheritdoc/>
        public byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicValue)
        {
            if (privateKey.Length != KeySize) throw new ArgumentException($"X25519 private key must be {KeySize} bytes.", nameof(privateKey));
            if (peerPublicValue.Length != KeySize) throw new ArgumentException($"X25519 public value must be {KeySize} bytes.", nameof(peerPublicValue));
            byte[] k = privateKey.ToArray();
            byte[] u = peerPublicValue.ToArray();
            byte[] shared = new byte[KeySize];
            X25519.ScalarMult(k, 0, u, 0, shared, 0);
            return shared;
        }
    }
}
