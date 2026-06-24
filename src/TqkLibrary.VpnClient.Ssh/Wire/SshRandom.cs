using System.Security.Cryptography;

namespace TqkLibrary.VpnClient.Ssh.Wire
{
    /// <summary>Cryptographic random fill that works on both target frameworks (net6+ <c>RandomNumberGenerator.Fill</c> is not on netstandard2.0).</summary>
    internal static class SshRandom
    {
        /// <summary>Fills <paramref name="destination"/> with cryptographically-strong random bytes.</summary>
        public static void Fill(Span<byte> destination)
        {
#if NET6_0_OR_GREATER
            RandomNumberGenerator.Fill(destination);
#else
            byte[] tmp = new byte[destination.Length];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(tmp);
            tmp.CopyTo(destination);
#endif
        }

        /// <summary>Returns a fresh array of <paramref name="count"/> cryptographically-strong random bytes.</summary>
        public static byte[] Bytes(int count)
        {
            byte[] b = new byte[count];
            Fill(b);
            return b;
        }
    }
}
