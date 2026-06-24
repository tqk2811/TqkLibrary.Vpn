using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.N2n.Transform.Interfaces;

namespace TqkLibrary.VpnClient.N2n.Transform
{
    /// <summary>
    /// n2n v3 AES transform (<c>transop_aes</c>, <see cref="Wire.Enums.N2nTransformId.Aes"/> = 3). It protects a PACKET
    /// payload (the inner Ethernet frame) with AES-CBC and a <b>null IV</b>: a random 16-byte preamble (one AES block)
    /// is prepended to the plaintext and the whole thing is zero-padded to a block boundary, then CBC-encrypted. Because
    /// CBC chains from a zero IV, that random first block randomizes every subsequent block — so no separate IV travels
    /// on the wire. The output is the ciphertext only; the receiver decrypts, drops the 16-byte preamble, and the
    /// remaining (zero-padded) bytes are the frame. The AES key (16/24/32 bytes) is supplied by the caller — this type
    /// does not derive it from the community password (n2n's Pearson-hash key derivation is out of scope; pass the key
    /// directly or use <see cref="Wire.Enums.N2nTransformId.Null"/> to send frames in the clear).
    /// <para>Reuses <see cref="AesCbcCipher"/> (no re-implemented AES).</para>
    /// </summary>
    public sealed class N2nAesTransform : IN2nTransform
    {
        /// <summary>Random preamble length (<c>AES_PREAMBLE_SIZE</c>) — one AES block that doubles as the per-packet IV.</summary>
        public const int PreambleSize = 16;

        const int BlockSize = 16;

        readonly byte[] _key;
        readonly AesCbcCipher _cbc = new AesCbcCipher();

        /// <summary>Creates the transform with an AES key (must be 16, 24 or 32 bytes).</summary>
        public N2nAesTransform(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("AES key must be 16, 24 or 32 bytes.", nameof(key));
            _key = key.ToArray();
        }

        /// <inheritdoc/>
        public Wire.Enums.N2nTransformId Id => Wire.Enums.N2nTransformId.Aes;

        /// <inheritdoc/>
        public byte[] Encode(ReadOnlySpan<byte> plaintext)
        {
            // [random preamble(16)] ‖ plaintext, zero-padded to a block boundary, AES-CBC with null IV.
            int assembledLen = PreambleSize + plaintext.Length;
            int paddedLen = RoundUpToBlock(assembledLen);
            byte[] buf = new byte[paddedLen];
            FillRandom(buf.AsSpan(0, PreambleSize));
            plaintext.CopyTo(buf.AsSpan(PreambleSize));
            // bytes [assembledLen..paddedLen) stay zero (pad).

            byte[] iv = new byte[BlockSize]; // null IV
            byte[] outBuf = new byte[paddedLen];
            _cbc.Encrypt(_key, iv, buf, outBuf);
            return outBuf;
        }

        /// <inheritdoc/>
        public byte[] Decode(ReadOnlySpan<byte> ciphertext)
        {
            if (ciphertext.Length < PreambleSize + BlockSize || ciphertext.Length % BlockSize != 0)
                throw new ArgumentException("ciphertext is not a valid AES-CBC n2n payload.", nameof(ciphertext));

            byte[] iv = new byte[BlockSize]; // null IV
            byte[] plain = new byte[ciphertext.Length];
            _cbc.Decrypt(_key, iv, ciphertext, plain);
            // Drop the 16-byte random preamble; the rest (including any zero padding) is the frame.
            return plain.AsSpan(PreambleSize).ToArray();
        }

        static int RoundUpToBlock(int n) => (n + BlockSize - 1) / BlockSize * BlockSize;

        static void FillRandom(Span<byte> dst)
        {
#if NET6_0_OR_GREATER
            System.Security.Cryptography.RandomNumberGenerator.Fill(dst);
#else
            byte[] tmp = new byte[dst.Length];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(tmp);
            tmp.CopyTo(dst);
#endif
        }
    }
}
