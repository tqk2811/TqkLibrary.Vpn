using System.Buffers.Binary;

namespace TqkLibrary.VpnClient.WireGuard.DataChannel
{
    /// <summary>
    /// Serialises and parses the WireGuard transport-data message (type 4, whitepaper §5.4.6) byte-for-byte. The cleartext
    /// header is <c>type(1) | reserved(3) | receiver_index(4 LE) | counter(8 LE)</c> followed by the AEAD output
    /// (ciphertext ‖ 16-byte tag); a keepalive carries an empty payload, so its encrypted part is just the tag. Both the
    /// receiver index and the 64-bit counter are <b>little-endian</b>; the type byte is followed by three reserved zero
    /// bytes. This codec only moves bytes — the AEAD itself is applied by <see cref="WireGuardTransport"/>.
    /// <code>
    ///   msg.transport = type(1) | reserved(3) | receiver(4) | counter(8) | enc_packet(N+16)
    ///   nonce(12)     = 0x00 00 00 00 ‖ counter(8 LE)        (4 zero bytes, then the little-endian counter)
    ///   AAD           = ∅                                     (WireGuard authenticates the header via the nonce)
    /// </code>
    /// </summary>
    public sealed class WireGuardDataCodec
    {
        const int TypeOffset = 0;                                                 // 1 byte type + 3 reserved
        const int ReceiverOffset = 4;                                             // 4 (little-endian)
        const int CounterOffset = ReceiverOffset + WireGuardConstants.IndexLength;          // 8 (little-endian, 8 bytes)

        /// <summary>Length of the 8-byte little-endian transport counter.</summary>
        public const int CounterLength = 8;

        /// <summary>ChaCha20-Poly1305 nonce length: 4 zero bytes followed by the 8-byte little-endian counter (12 bytes).</summary>
        public const int NonceLength = 4 + CounterLength;

        /// <summary>Length of the cleartext transport-data header — <c>type+reserved+receiver+counter</c> (16 bytes).</summary>
        public const int HeaderLength = CounterOffset + CounterLength;            // 16

        /// <summary>Minimum length of a transport-data datagram: the header plus the 16-byte tag of an empty payload.</summary>
        public const int MinimumLength = HeaderLength + WireGuardConstants.TagLength; // 32

        /// <summary>
        /// Writes the 16-byte cleartext transport-data header (type 4, the receiver index and the counter) into the
        /// front of <paramref name="datagram"/>. The caller fills the AEAD output after offset <see cref="HeaderLength"/>.
        /// </summary>
        public void WriteHeader(Span<byte> datagram, uint receiverIndex, ulong counter)
        {
            if (datagram.Length < HeaderLength) throw new ArgumentException("datagram too small for the transport-data header.", nameof(datagram));
            datagram[TypeOffset] = WireGuardConstants.MessageTypeTransportData; // next 3 bytes stay zero (reserved)
            datagram[1] = 0; datagram[2] = 0; datagram[3] = 0;
            BinaryPrimitives.WriteUInt32LittleEndian(datagram.Slice(ReceiverOffset, WireGuardConstants.IndexLength), receiverIndex);
            BinaryPrimitives.WriteUInt64LittleEndian(datagram.Slice(CounterOffset, CounterLength), counter);
        }

        /// <summary>
        /// Validates and reads the cleartext header of a transport-data datagram. Returns <c>false</c> (no exception)
        /// when the length is below <see cref="MinimumLength"/>, the type byte is not <c>4</c>, or a reserved byte is
        /// non-zero, so a malformed/foreign datagram is simply dropped before any AEAD work.
        /// </summary>
        public bool TryReadHeader(ReadOnlySpan<byte> datagram, out uint receiverIndex, out ulong counter)
        {
            receiverIndex = 0;
            counter = 0;
            if (datagram.Length < MinimumLength) return false;
            if (datagram[TypeOffset] != WireGuardConstants.MessageTypeTransportData) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;
            receiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(ReceiverOffset, WireGuardConstants.IndexLength));
            counter = BinaryPrimitives.ReadUInt64LittleEndian(datagram.Slice(CounterOffset, CounterLength));
            return true;
        }

        /// <summary>
        /// Builds the 12-byte ChaCha20-Poly1305 nonce for <paramref name="counter"/>: four zero bytes followed by the
        /// counter encoded little-endian (whitepaper §5.4.6). The same counter therefore drives both the nonce and the
        /// wire field, so it must never repeat for a transport key.
        /// </summary>
        public void WriteNonce(Span<byte> nonce, ulong counter)
        {
            if (nonce.Length < NonceLength)
                throw new ArgumentException("nonce must be at least 12 bytes.", nameof(nonce));
            nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(4, CounterLength), counter);
        }
    }
}
