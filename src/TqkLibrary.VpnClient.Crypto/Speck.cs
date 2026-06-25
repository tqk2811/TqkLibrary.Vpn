using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.Crypto
{
    /// <summary>
    /// The SPECK 128/128 ARX block cipher (NSA, Beaulieu et al. 2013) as used by <b>n2n v3 header encryption</b>
    /// (<c>-H</c>). SPECK is a 128-bit-block, 128-bit-key cipher built from add-rotate-xor on two 64-bit words; n2n picks
    /// it because it is fast in software and offers a 128-bit block. This is a small, self-contained implementation
    /// (BouncyCastle ships no SPECK on either target framework) verified byte-exact against the n2n reference (golden
    /// vectors captured from <c>libn2n.a</c> v3.1.1) and the NSA Speck128/128 test vector — see <c>SpeckTests</c>.
    /// <para>
    /// <b>Word/byte order matches n2n exactly</b> (this is interop-critical): the 16-byte key and 16-byte block are read
    /// as two <b>little-endian</b> 64-bit words — low word first (bytes 0..7), high word second (bytes 8..15). The round
    /// function is <c>x = ror(x,8) + y; x ^= k; y = rol(y,3) ^ x</c> applied 32 times with <c>key[i]</c>.
    /// </para>
    /// ⚠️ SPECK is exposed here only to interoperate with n2n's header-encryption (<c>header_encryption.c</c>); it is not
    /// a recommended general-purpose cipher. Use AES/ChaCha20 for payload confidentiality.
    /// </summary>
    public sealed class Speck
    {
        /// <summary>SPECK-128 block size in bytes (128-bit block = two 64-bit words).</summary>
        public const int BlockSizeInBytes = 16;

        const int Rounds = 32;       // Speck128/128: 32 rounds (the 34-key schedule fills key[32]/key[33] but they are unused).
        const int KeyCount = 34;

        readonly ulong[] _roundKeys = new ulong[KeyCount];

        /// <summary>Creates a SPECK-128/128 cipher and expands the 16-byte <paramref name="key"/> into the round-key schedule.</summary>
        public Speck(ReadOnlySpan<byte> key)
        {
            if (key.Length != 16) throw new ArgumentException("SPECK-128/128 key must be 16 bytes.", nameof(key));
            ExpandKey(key);
        }

        // Round function R(x,y,k): x = ror(x,8) + y; x ^= k; y = rol(y,3); y ^= x  (matches n2n's R macro).
        static void Round(ref ulong x, ref ulong y, ulong k)
        {
            x = Ror(x, 8);
            x += y;
            x ^= k;
            y = Rol(y, 3);
            y ^= x;
        }

        // Inverse round (for decrypt): y ^= x; y = ror(y,3); x ^= k; x -= y; x = rol(x,8).
        static void InvRound(ref ulong x, ref ulong y, ulong k)
        {
            y ^= x;
            y = Ror(y, 3);
            x ^= k;
            x -= y;
            x = Rol(x, 8);
        }

        static ulong Ror(ulong v, int r) => (v >> r) | (v << (64 - r));
        static ulong Rol(ulong v, int r) => (v << r) | (v >> (64 - r));

        void ExpandKey(ReadOnlySpan<byte> key)
        {
            // K[0] = LE word(key[0..7]); K[1] = LE word(key[8..15]).
            ulong k0 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(0, 8));
            ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(8, 8));
            for (int i = 0; i < Rounds; i++)
            {
                _roundKeys[i] = k0;
                Round(ref k1, ref k0, (ulong)i);   // generates the next l/k pair (n2n: R(K[1], K[0], i))
            }
        }

        /// <summary>Encrypts the 16-byte block <paramref name="block"/> in place (ECB single-block).</summary>
        public void EncryptBlock(Span<byte> block)
        {
            if (block.Length != BlockSizeInBytes) throw new ArgumentException("SPECK block must be 16 bytes.", nameof(block));
            // y = low word (bytes 0..7), x = high word (bytes 8..15).
            ulong y = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(0, 8));
            ulong x = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(8, 8));
            for (int i = 0; i < Rounds; i++) Round(ref x, ref y, _roundKeys[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0, 8), y);
            BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8, 8), x);
        }

        /// <summary>Decrypts the 16-byte block <paramref name="block"/> in place (ECB single-block).</summary>
        public void DecryptBlock(Span<byte> block)
        {
            if (block.Length != BlockSizeInBytes) throw new ArgumentException("SPECK block must be 16 bytes.", nameof(block));
            ulong y = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(0, 8));
            ulong x = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(8, 8));
            for (int i = Rounds - 1; i >= 0; i--) InvRound(ref x, ref y, _roundKeys[i]);
            BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(0, 8), y);
            BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8, 8), x);
        }

        /// <summary>
        /// SPECK in counter (CTR) mode, XOR-ing <paramref name="input"/> with the keystream into <paramref name="output"/>
        /// (same length). The 16-byte <paramref name="iv"/> seeds the counter as two little-endian 64-bit words
        /// (<c>nonce0 = LE(iv[0..7])</c>, <c>nonce1 = LE(iv[8..15])</c>); per block the cipher encrypts
        /// <c>(x=nonce1, y=nonce0)</c> and increments <c>nonce0</c> (mod 2^64), matching n2n's <c>speck_ctr</c>. The final
        /// partial block reuses the same (un-incremented) keystream block for the remaining &lt;16 bytes. Encryption and
        /// decryption are the identical call.
        /// </summary>
        public void Ctr(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (iv.Length != BlockSizeInBytes) throw new ArgumentException("SPECK CTR IV must be 16 bytes.", nameof(iv));
            if (output.Length < input.Length) throw new ArgumentException("output too small", nameof(output));

            ulong nonce0 = BinaryPrimitives.ReadUInt64LittleEndian(iv.Slice(0, 8));
            ulong nonce1 = BinaryPrimitives.ReadUInt64LittleEndian(iv.Slice(8, 8));

            Span<byte> ks = stackalloc byte[BlockSizeInBytes];
            int off = 0;
            int len = input.Length;
            while (len >= BlockSizeInBytes)
            {
                ulong x = nonce1, y = nonce0;
                nonce0++;
                for (int i = 0; i < Rounds; i++) Round(ref x, ref y, _roundKeys[i]);
                // keystream block = LE(y) ‖ LE(x)
                BinaryPrimitives.WriteUInt64LittleEndian(ks.Slice(0, 8), y);
                BinaryPrimitives.WriteUInt64LittleEndian(ks.Slice(8, 8), x);
                for (int i = 0; i < BlockSizeInBytes; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
                off += BlockSizeInBytes;
                len -= BlockSizeInBytes;
            }
            if (len > 0)
            {
                // Final partial block: same nonce (NOT incremented past it), XOR the leading `len` bytes.
                ulong x = nonce1, y = nonce0;
                for (int i = 0; i < Rounds; i++) Round(ref x, ref y, _roundKeys[i]);
                BinaryPrimitives.WriteUInt64LittleEndian(ks.Slice(0, 8), y);
                BinaryPrimitives.WriteUInt64LittleEndian(ks.Slice(8, 8), x);
                for (int i = 0; i < len; i++) output[off + i] = (byte)(input[off + i] ^ ks[i]);
            }
        }
    }
}
