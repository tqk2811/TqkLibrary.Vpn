using TqkLibrary.Vpn.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.Vpn.Crypto
{
    /// <summary>
    /// The IKEv2 key-expansion function prf+ (RFC 7296 §2.13):
    /// <c>prf+(K,S) = T1 | T2 | T3 | …</c> where <c>T1 = prf(K, S|0x01)</c> and <c>Tn = prf(K, T(n-1)|S|n)</c>.
    /// </summary>
    public static class PrfPlus
    {
        /// <summary>Expands <paramref name="seed"/> keyed by <paramref name="key"/> into <paramref name="length"/> bytes.</summary>
        public static byte[] Expand(IPrf prf, ReadOnlySpan<byte> key, ReadOnlySpan<byte> seed, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            int macLength = prf.OutputSizeInBytes;
            byte[] result = new byte[length];
            byte[] keyArray = key.ToArray();
            byte[] seedArray = seed.ToArray();

            byte[] previous = Array.Empty<byte>();
            byte[] block = new byte[macLength];
            int produced = 0;
            byte counter = 1;

            while (produced < length)
            {
                // Tn = prf(K, T(n-1) | S | n)
                byte[] input = new byte[previous.Length + seedArray.Length + 1];
                Buffer.BlockCopy(previous, 0, input, 0, previous.Length);
                Buffer.BlockCopy(seedArray, 0, input, previous.Length, seedArray.Length);
                input[input.Length - 1] = counter;

                prf.Compute(keyArray, input, block);

                int take = Math.Min(macLength, length - produced);
                Buffer.BlockCopy(block, 0, result, produced, take);
                produced += take;

                previous = (byte[])block.Clone();
                counter++;
                if (counter == 0) throw new InvalidOperationException("prf+ exceeded 255 iterations.");
            }
            return result;
        }
    }
}
