using System;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
// Alias the two BouncyCastle primitives rather than importing the namespace wholesale (its Crypto namespace clashes
// with this solution's interfaces — see Crypto/Noise/Curve25519DhGroup for the same pattern).
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The SPTPS key-exchange Diffie-Hellman as tinc implements it (orlp ed25519 <c>ecdh.c</c> + <c>key_exchange.c</c>)
    /// — <b>not</b> plain X25519. The ephemeral KEX keypair is an <b>Ed25519</b> keypair: the public value on the wire
    /// is the Ed25519 <b>Edwards-form</b> public key (<c>ge_scalarmult_base</c> of the clamped SHA-512(seed) scalar),
    /// and the shared secret is computed by converting the peer's Edwards public to its Montgomery x-coordinate
    /// (<c>montgomeryX = (1 + y) / (1 - y) mod p</c>) and running the X25519 Montgomery ladder with the clamped scalar.
    /// <para>
    /// This differs from <see cref="Crypto.Noise.Curve25519DhGroup"/> (plain X25519, Montgomery public on the wire) in
    /// both the public encoding and the scalar derivation, so the two produce different shared secrets for the same
    /// key material — using X25519 directly makes tinc's SPTPS record cipher fail (the handshake SIG still verifies
    /// because it never touches the ECDH secret; found live against tincd 1.1pre18).
    /// </para>
    /// Reuses BouncyCastle's <c>Ed25519.GeneratePublicKey</c> (Edwards base mult) and <c>X25519.ScalarMult</c> (ladder).
    /// </summary>
    public sealed class SptpsEcdh : IDhGroup
    {
        const int KeySize = 32;

        // Field prime p = 2^255 - 19.
        static readonly BcBigInteger P =
            BcBigInteger.Two.Pow(255).Subtract(BcBigInteger.ValueOf(19));

        static SptpsEcdh()
        {
            BcX25519.Precompute();
        }

        /// <inheritdoc/>
        public int GroupId => 31; // Curve25519 family; SPTPS uses an Ed25519-keyed variant.

        /// <inheritdoc/>
        public int PublicValueSizeInBytes => KeySize;

        /// <summary>Generates a fresh 32-byte Ed25519 seed (the ephemeral KEX private key).</summary>
        public byte[] GeneratePrivateKey()
        {
            byte[] seed = new byte[KeySize];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(seed);
            return seed;
        }

        /// <summary>Derives the Ed25519 (Edwards-form) public value sent in the KEX message.</summary>
        public byte[] DerivePublicValue(ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != KeySize) throw new ArgumentException($"SPTPS ECDH seed must be {KeySize} bytes.", nameof(privateKey));
            byte[] seed = privateKey.ToArray();
            byte[] pub = new byte[KeySize];
            BcEd25519.GeneratePublicKey(seed, 0, pub, 0); // ge_scalarmult_base(clamp(SHA512(seed)))
            return pub;
        }

        /// <summary>
        /// Computes the shared secret: convert the peer's Edwards public to Montgomery x, then run X25519 with the
        /// clamped SHA-512(seed) scalar (orlp <c>ed25519_key_exchange</c>).
        /// </summary>
        public byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicValue)
        {
            if (privateKey.Length != KeySize) throw new ArgumentException($"SPTPS ECDH seed must be {KeySize} bytes.", nameof(privateKey));
            if (peerPublicValue.Length != KeySize) throw new ArgumentException($"SPTPS ECDH public must be {KeySize} bytes.", nameof(peerPublicValue));

            byte[] scalar = ClampedScalar(privateKey);
            byte[] u = EdwardsToMontgomeryX(peerPublicValue);
            byte[] shared = new byte[KeySize];
            BcX25519.ScalarMult(scalar, 0, u, 0, shared, 0);
            return shared;
        }

        /// <summary>The X25519 scalar tinc uses: <c>SHA-512(seed)[0..32]</c> with the standard clamp bits.</summary>
        static byte[] ClampedScalar(ReadOnlySpan<byte> seed)
        {
            byte[] h;
            using (var sha = SHA512.Create())
                h = sha.ComputeHash(seed.ToArray());
            byte[] scalar = new byte[KeySize];
            Array.Copy(h, scalar, KeySize);
            scalar[0] &= 248;
            scalar[31] &= 63;
            scalar[31] |= 64;
            return scalar;
        }

        /// <summary>
        /// Converts an Ed25519 Edwards public key to its Montgomery x-coordinate (little-endian, 32 bytes):
        /// <c>u = (1 + y) * (1 - y)^-1 mod p</c>, where <c>y</c> is the public key's field element (high bit, the x
        /// sign, cleared — exactly <c>fe_frombytes</c>).
        /// </summary>
        static byte[] EdwardsToMontgomeryX(ReadOnlySpan<byte> edwardsPublic)
        {
            // y = little-endian field element, top bit masked off (drop the x-sign bit, like fe_frombytes).
            byte[] le = edwardsPublic.ToArray();
            le[31] &= 0x7f;
            BcBigInteger y = FromLittleEndian(le);

            BcBigInteger one = BcBigInteger.One;
            BcBigInteger num = one.Add(y).Mod(P);                  // 1 + y
            BcBigInteger den = one.Subtract(y).Mod(P);             // 1 - y
            BcBigInteger u = num.Multiply(den.ModInverse(P)).Mod(P);
            return ToLittleEndian(u, KeySize);
        }

        static BcBigInteger FromLittleEndian(byte[] le)
        {
            byte[] be = new byte[le.Length];
            for (int i = 0; i < le.Length; i++) be[i] = le[le.Length - 1 - i];
            return new BcBigInteger(1, be); // positive
        }

        static byte[] ToLittleEndian(BcBigInteger value, int length)
        {
            byte[] be = value.ToByteArrayUnsigned(); // big-endian, no sign byte
            byte[] le = new byte[length];
            for (int i = 0; i < be.Length && i < length; i++)
                le[i] = be[be.Length - 1 - i];
            return le;
        }
    }
}
