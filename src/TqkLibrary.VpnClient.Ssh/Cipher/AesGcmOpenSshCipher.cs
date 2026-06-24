using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;

namespace TqkLibrary.VpnClient.Ssh.Cipher
{
    /// <summary>
    /// The <c>aes128-gcm@openssh.com</c> / <c>aes256-gcm@openssh.com</c> packet cipher (OpenSSH PROTOCOL §1.6, RFC 5647).
    /// Unlike chacha20-poly1305@openssh.com the 4-byte packet length is sent <b>in the clear</b> and authenticated as
    /// AES-GCM additional data; the rest of the binary packet (<c>padding_length || payload || padding</c>) is encrypted.
    /// The 12-byte GCM IV is a 4-byte fixed field followed by an 8-byte invocation counter taken from the KDF and
    /// incremented (as a big-endian integer) after every packet — the sequence number is <b>not</b> used as the nonce.
    /// AES-GCM carries its own 16-byte tag, so no separate MAC is negotiated. The KDF supplies the key (16 or 32 bytes)
    /// and then the 12-byte initial IV for this direction.
    /// </summary>
    public sealed class AesGcmOpenSshCipher : ISshPacketCipher
    {
        const int TagBytes = 16;
        const int IvBytes = 12;
        const int FixedIvBytes = 4;

        readonly IAeadCipher _aead;
        readonly byte[] _key;
        readonly byte[] _iv; // 12 bytes: 4 fixed || 8 invocation counter (mutated per packet)

        /// <summary>AES-256 key length in bytes (aes256-gcm@openssh.com).</summary>
        public const int Aes256KeyBytes = 32;

        /// <summary>AES-128 key length in bytes (aes128-gcm@openssh.com).</summary>
        public const int Aes128KeyBytes = 16;

        /// <summary>The IV length the KDF must supply for this direction (12 bytes).</summary>
        public const int IvMaterialBytes = IvBytes;

        /// <summary>
        /// Builds the cipher for one direction from the derived <paramref name="key"/> (16 or 32 bytes) and the 12-byte
        /// initial <paramref name="iv"/> (4 fixed + 8 invocation counter) from the SSH KDF.
        /// </summary>
        public AesGcmOpenSshCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            if (key.Length != Aes128KeyBytes && key.Length != Aes256KeyBytes)
                throw new ArgumentException("aes-gcm@openssh.com key must be 16 or 32 bytes.", nameof(key));
            if (iv.Length < IvBytes) throw new ArgumentException("aes-gcm@openssh.com IV must be 12 bytes.", nameof(iv));
            _key = key.ToArray();
            _iv = iv.Slice(0, IvBytes).ToArray();
            _aead = new AesGcmCipher(_key.Length);
        }

        /// <inheritdoc/>
        public int BlockSize => 16; // AES block size — the binary packet pads to a 16-byte boundary

        /// <inheritdoc/>
        public int TagLength => TagBytes;

        /// <inheritdoc/>
        public bool LengthIsEncrypted => false; // the length is cleartext and used as additional data

        // RFC 5647: after each packet the 8-byte invocation counter (the low 8 bytes of the IV) is incremented as a
        // big-endian integer, with the 4-byte fixed field left unchanged.
        void IncrementIv()
        {
            for (int i = IvBytes - 1; i >= FixedIvBytes; i--)
            {
                if (++_iv[i] != 0) break;
            }
        }

        /// <inheritdoc/>
        public byte[] Seal(ReadOnlySpan<byte> packet, uint sequenceNumber)
        {
            // packet = uint32 length || body. The length is AAD (cleartext); the body is encrypted.
            ReadOnlySpan<byte> aad = packet.Slice(0, 4);
            ReadOnlySpan<byte> body = packet.Slice(4);

            byte[] result = new byte[packet.Length + TagBytes];
            aad.CopyTo(result);
            Span<byte> ciphertext = result.AsSpan(4, body.Length);
            Span<byte> tag = result.AsSpan(4 + body.Length, TagBytes);
            _aead.Seal(_key, _iv, body, aad, ciphertext, tag);

            IncrementIv();
            return result;
        }

        /// <inheritdoc/>
        public uint ReadLength(ReadOnlySpan<byte> firstFourBytes, uint sequenceNumber)
            => (uint)((firstFourBytes[0] << 24) | (firstFourBytes[1] << 16) | (firstFourBytes[2] << 8) | firstFourBytes[3]);

        /// <inheritdoc/>
        public bool Open(ReadOnlySpan<byte> wirePacket, uint packetLength, uint sequenceNumber, Span<byte> plaintext)
        {
            int bodyLen = (int)packetLength;
            if (wirePacket.Length < 4 + bodyLen + TagBytes) return false;

            ReadOnlySpan<byte> aad = wirePacket.Slice(0, 4);
            ReadOnlySpan<byte> ciphertext = wirePacket.Slice(4, bodyLen);
            ReadOnlySpan<byte> tag = wirePacket.Slice(4 + bodyLen, TagBytes);

            aad.CopyTo(plaintext);
            bool ok = _aead.Open(_key, _iv, ciphertext, tag, aad, plaintext.Slice(4, bodyLen));
            IncrementIv(); // the receiver advances its IV per packet too, matched to the sender
            return ok;
        }
    }
}
