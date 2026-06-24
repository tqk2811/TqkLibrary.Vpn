namespace TqkLibrary.VpnClient.Ssh.Cipher
{
    /// <summary>
    /// One direction of an established SSH binary-packet cipher (RFC 4253 §6) — the seam the
    /// <see cref="Wire.SshPacketCodec"/> drives once NEWKEYS has installed the negotiated algorithm. An implementation
    /// owns the encryption + MAC for a packet given its sequence number; the codec frames the cleartext (payload + random
    /// padding) and hands the whole binary packet (the 4-byte length included) to <see cref="Seal"/>, and feeds inbound
    /// bytes to <see cref="ReadLength"/> then <see cref="Open"/>. This abstracts the difference between an Encrypt-then-MAC
    /// stream cipher, an AEAD (aes*-gcm@openssh.com) and the chacha20-poly1305@openssh.com construction (which encrypts
    /// the packet length separately) behind one interface.
    /// </summary>
    public interface ISshPacketCipher
    {
        /// <summary>The cipher block size in bytes (the multiple the padding rounds the packet to). 8 for the stream/AEAD ciphers here.</summary>
        int BlockSize { get; }

        /// <summary>The trailing authentication tag / MAC length in bytes appended to each packet.</summary>
        int TagLength { get; }

        /// <summary>
        /// True when the 4-byte packet-length field is encrypted (and therefore not authenticated by being part of the
        /// AEAD additional data) — i.e. the chacha20-poly1305@openssh.com layout, where the length must be decrypted with
        /// a separate key before the rest is read. False for aes*-gcm@openssh.com, where the length is sent in the clear
        /// and authenticated as additional data.
        /// </summary>
        bool LengthIsEncrypted { get; }

        /// <summary>
        /// Encrypts and authenticates one outbound binary packet. <paramref name="packet"/> is the cleartext binary packet
        /// <c>uint32 packet_length || byte padding_length || payload || random padding</c> (RFC 4253 §6). Returns the wire
        /// bytes (the encrypted packet followed by the <see cref="TagLength"/>-byte tag). <paramref name="sequenceNumber"/>
        /// is the outbound packet sequence number (it is the AEAD nonce material).
        /// </summary>
        byte[] Seal(ReadOnlySpan<byte> packet, uint sequenceNumber);

        /// <summary>
        /// Returns the plaintext packet length given the first 4 wire bytes of an inbound packet and its
        /// <paramref name="sequenceNumber"/>. For aes*-gcm the 4 bytes are already the cleartext length; for
        /// chacha20-poly1305 they are decrypted with the length key. The returned value is <c>padding_length + payload +
        /// padding</c> (it does <b>not</b> include the 4 length bytes nor the tag).
        /// </summary>
        uint ReadLength(ReadOnlySpan<byte> firstFourBytes, uint sequenceNumber);

        /// <summary>
        /// Verifies and decrypts one inbound binary packet. <paramref name="wirePacket"/> is the full on-wire packet:
        /// the 4 length bytes (as received — possibly encrypted), the encrypted <c>packetLength</c> body and the
        /// <see cref="TagLength"/>-byte tag. On success writes the cleartext binary packet (length-field + body) to
        /// <paramref name="plaintext"/> and returns true; returns false (writing nothing) if authentication fails.
        /// </summary>
        bool Open(ReadOnlySpan<byte> wirePacket, uint packetLength, uint sequenceNumber, Span<byte> plaintext);
    }
}
