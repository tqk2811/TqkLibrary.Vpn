using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;

namespace TqkLibrary.VpnClient.Ipsec.Esp
{
    /// <summary>
    /// ESP with AES-GCM AEAD (RFC 4106): one key provides both confidentiality and integrity. The 12-byte GCM nonce
    /// is salt(4) ‖ explicit-IV(8); the IV is the ESP sequence number, unique within the SA. SPI ‖ Seq is the AAD.
    /// Wire layout: SPI(4) | Seq(4) | IV(8) | ciphertext | ICV/tag(16).
    /// </summary>
    public sealed class EspGcmSuite : EspCipherSuite
    {
        const int SaltSize = 4;
        const int IvSize = 8;
        const int Alignment = 4; // RFC 4106 §3: plaintext is padded so it ends on a 4-byte boundary.

        readonly byte[] _key;
        readonly byte[] _salt;
        readonly IAeadCipher _aead;

        /// <summary>Creates the suite with an AES key (16/24/32 bytes) and a 4-byte salt, both from IKE key material.</summary>
        public EspGcmSuite(byte[] key, byte[] salt)
        {
            if (salt.Length != SaltSize) throw new ArgumentException("AES-GCM ESP salt must be 4 bytes.", nameof(salt));
            _key = key;
            _salt = salt;
            _aead = new AesGcmCipher(key.Length);
        }

        /// <inheritdoc/>
        public override byte[] Protect(uint spi, uint sequence, ReadOnlySpan<byte> payload, byte nextHeader)
        {
            int unpadded = payload.Length + 2;
            int padLength = (Alignment - (unpadded % Alignment)) % Alignment;
            int plainLength = unpadded + padLength;

            byte[] plain = new byte[plainLength];
            payload.CopyTo(plain);
            for (int i = 0; i < padLength; i++)
                plain[payload.Length + i] = (byte)(i + 1);
            plain[plainLength - 2] = (byte)padLength;
            plain[plainLength - 1] = nextHeader;

            int tagSize = _aead.TagSizeInBytes;
            byte[] packet = new byte[EspConstants.HeaderSize + IvSize + plainLength + tagSize];
            EspConstants.WriteHeader(packet, spi, sequence);
            // Explicit IV = big-endian sequence number (unique per packet within the SA).
            WriteSequenceIv(packet.AsSpan(EspConstants.HeaderSize, IvSize), sequence);

            Span<byte> nonce = stackalloc byte[SaltSize + IvSize];
            _salt.CopyTo(nonce);
            packet.AsSpan(EspConstants.HeaderSize, IvSize).CopyTo(nonce.Slice(SaltSize));

            ReadOnlySpan<byte> aad = packet.AsSpan(0, EspConstants.HeaderSize);
            Span<byte> cipherText = packet.AsSpan(EspConstants.HeaderSize + IvSize, plainLength);
            Span<byte> tag = packet.AsSpan(EspConstants.HeaderSize + IvSize + plainLength, tagSize);
            _aead.Seal(_key, nonce, plain, aad, cipherText, tag);
            return packet;
        }

        /// <inheritdoc/>
        public override bool TryUnprotect(ReadOnlySpan<byte> packet, out byte[] payload, out byte nextHeader)
        {
            payload = Array.Empty<byte>();
            nextHeader = 0;

            int tagSize = _aead.TagSizeInBytes;
            int minLength = EspConstants.HeaderSize + IvSize + Alignment + tagSize;
            if (packet.Length < minLength) return false;

            int cipherLength = packet.Length - EspConstants.HeaderSize - IvSize - tagSize;
            if (cipherLength <= 0 || cipherLength % Alignment != 0) return false;

            Span<byte> nonce = stackalloc byte[SaltSize + IvSize];
            _salt.CopyTo(nonce);
            packet.Slice(EspConstants.HeaderSize, IvSize).CopyTo(nonce.Slice(SaltSize));

            ReadOnlySpan<byte> aad = packet.Slice(0, EspConstants.HeaderSize);
            ReadOnlySpan<byte> cipherText = packet.Slice(EspConstants.HeaderSize + IvSize, cipherLength);
            ReadOnlySpan<byte> tag = packet.Slice(EspConstants.HeaderSize + IvSize + cipherLength, tagSize);

            byte[] plain = new byte[cipherLength];
            if (!_aead.Open(_key, nonce, cipherText, tag, aad, plain)) return false;
            return TryStripTrailer(plain, out payload, out nextHeader);
        }

        static void WriteSequenceIv(Span<byte> iv, uint sequence)
        {
            // High 4 bytes are zero (no Extended Sequence Numbers); low 4 bytes carry the sequence, big-endian.
            iv[0] = 0; iv[1] = 0; iv[2] = 0; iv[3] = 0;
            iv[4] = (byte)(sequence >> 24); iv[5] = (byte)(sequence >> 16); iv[6] = (byte)(sequence >> 8); iv[7] = (byte)sequence;
        }
    }
}
