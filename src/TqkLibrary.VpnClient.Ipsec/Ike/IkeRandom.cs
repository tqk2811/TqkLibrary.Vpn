using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Ipsec.Ike
{
    /// <summary>
    /// Cryptographic RNG helpers shared by the IKEv1/IKEv2 clients (SPIs, nonces, cookies, message ids).
    /// Centralises the <see cref="RandomNumberGenerator"/> boilerplate that was previously duplicated across
    /// IkeV1Client, IkeClient and IkeSaInitiator.
    /// </summary>
    internal static class IkeRandom
    {
        /// <summary>Returns <paramref name="length"/> cryptographically-strong random bytes.</summary>
        public static byte[] NextBytes(int length)
        {
            byte[] buffer = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(buffer);
            return buffer;
        }

        /// <summary>
        /// Returns <paramref name="length"/> random bytes guaranteed non-zero (byte 0 is forced to 1 if every byte
        /// happened to be zero) — IKE SPIs and cookies MUST be non-zero (RFC 7296 §3.1).
        /// </summary>
        public static byte[] NextNonZeroBytes(int length)
        {
            byte[] buffer = NextBytes(length);
            bool allZero = true;
            foreach (byte b in buffer) if (b != 0) { allZero = false; break; }
            if (allZero) buffer[0] = 1;
            return buffer;
        }

        /// <summary>Returns a random non-zero 32-bit value (big-endian assembled), forced to 1 if it came out zero.</summary>
        public static uint NextNonZeroUInt32()
        {
            byte[] b = NextBytes(4);
            uint value = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
            return value == 0 ? 1u : value;
        }
    }
}
