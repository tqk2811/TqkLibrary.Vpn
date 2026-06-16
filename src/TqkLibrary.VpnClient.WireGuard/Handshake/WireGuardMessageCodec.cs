using System.Buffers.Binary;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// Serialises and parses the two WireGuard handshake messages byte-for-byte (whitepaper §5.4.2/§5.4.3). All
    /// multi-byte scalars (the type word and the session indices) are <b>little-endian</b>; the type byte is
    /// followed by three reserved zero bytes. The codec only moves bytes — it does not touch the crypto state
    /// (<see cref="WireGuardHandshake"/> fills the encrypted fields) nor mac1/mac2 (filled by the V3.c machinery),
    /// so the trailing 32 mac bytes round-trip verbatim.
    /// </summary>
    public sealed class WireGuardMessageCodec
    {
        // ---- Type-1 initiation field offsets (148 bytes total) ----
        const int InitTypeOffset = 0;                                              // 1 byte type + 3 reserved
        const int InitSenderOffset = 4;                                            // 4
        const int InitEphemeralOffset = InitSenderOffset + WireGuardConstants.IndexLength;   // 8
        const int InitStaticOffset = InitEphemeralOffset + WireGuardConstants.KeyLength;     // 40
        const int InitStaticLength = WireGuardConstants.KeyLength + WireGuardConstants.TagLength;        // 48
        const int InitTimestampOffset = InitStaticOffset + InitStaticLength;                 // 88
        const int InitTimestampLength = WireGuardConstants.TimestampLength + WireGuardConstants.TagLength; // 28
        const int InitMac1Offset = InitTimestampOffset + InitTimestampLength;                // 116
        const int InitMac2Offset = InitMac1Offset + WireGuardConstants.MacLength;            // 132

        // ---- Type-2 response field offsets (92 bytes total) ----
        const int RespTypeOffset = 0;                                              // 1 byte type + 3 reserved
        const int RespSenderOffset = 4;                                            // 4
        const int RespReceiverOffset = RespSenderOffset + WireGuardConstants.IndexLength;    // 8
        const int RespEphemeralOffset = RespReceiverOffset + WireGuardConstants.IndexLength; // 12
        const int RespEmptyOffset = RespEphemeralOffset + WireGuardConstants.KeyLength;      // 44
        const int RespEmptyLength = WireGuardConstants.TagLength;                            // 16 (empty payload → tag only)
        const int RespMac1Offset = RespEmptyOffset + RespEmptyLength;                        // 60
        const int RespMac2Offset = RespMac1Offset + WireGuardConstants.MacLength;            // 76

        /// <summary>
        /// The portion of an initiation message covered by mac1 — everything before the mac1 field (offset 0..115).
        /// V3.c keys BLAKE2s over this span.
        /// </summary>
        public const int InitiationMaccedLength = InitMac1Offset;

        /// <summary>The portion of a response message covered by mac1 — everything before the mac1 field (offset 0..59).</summary>
        public const int ResponseMaccedLength = RespMac1Offset;

        /// <summary>Encodes <paramref name="message"/> as a fresh 148-byte type-1 initiation datagram.</summary>
        public byte[] EncodeInitiation(WireGuardInitiationMessage message)
        {
            ValidateField(message.UnencryptedEphemeral, WireGuardConstants.KeyLength, nameof(message.UnencryptedEphemeral));
            ValidateField(message.EncryptedStatic, InitStaticLength, nameof(message.EncryptedStatic));
            ValidateField(message.EncryptedTimestamp, InitTimestampLength, nameof(message.EncryptedTimestamp));
            ValidateField(message.Mac1, WireGuardConstants.MacLength, nameof(message.Mac1));
            ValidateField(message.Mac2, WireGuardConstants.MacLength, nameof(message.Mac2));

            byte[] buffer = new byte[WireGuardConstants.InitiationMessageLength];
            buffer[InitTypeOffset] = WireGuardConstants.MessageTypeInitiation; // next 3 bytes stay zero (reserved)
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(InitSenderOffset, 4), message.SenderIndex);
            message.UnencryptedEphemeral.CopyTo(buffer.AsSpan(InitEphemeralOffset));
            message.EncryptedStatic.CopyTo(buffer.AsSpan(InitStaticOffset));
            message.EncryptedTimestamp.CopyTo(buffer.AsSpan(InitTimestampOffset));
            message.Mac1.CopyTo(buffer.AsSpan(InitMac1Offset));
            message.Mac2.CopyTo(buffer.AsSpan(InitMac2Offset));
            return buffer;
        }

        /// <summary>
        /// Parses a 148-byte type-1 initiation datagram. Returns <c>false</c> (no exception) when the length or the
        /// type/reserved bytes are wrong, so a malformed/foreign datagram is simply dropped.
        /// </summary>
        public bool TryDecodeInitiation(ReadOnlySpan<byte> datagram, out WireGuardInitiationMessage message)
        {
            message = null!;
            if (datagram.Length != WireGuardConstants.InitiationMessageLength) return false;
            if (datagram[InitTypeOffset] != WireGuardConstants.MessageTypeInitiation) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;

            message = new WireGuardInitiationMessage
            {
                SenderIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(InitSenderOffset, 4)),
                UnencryptedEphemeral = datagram.Slice(InitEphemeralOffset, WireGuardConstants.KeyLength).ToArray(),
                EncryptedStatic = datagram.Slice(InitStaticOffset, InitStaticLength).ToArray(),
                EncryptedTimestamp = datagram.Slice(InitTimestampOffset, InitTimestampLength).ToArray(),
                Mac1 = datagram.Slice(InitMac1Offset, WireGuardConstants.MacLength).ToArray(),
                Mac2 = datagram.Slice(InitMac2Offset, WireGuardConstants.MacLength).ToArray(),
            };
            return true;
        }

        /// <summary>Encodes <paramref name="message"/> as a fresh 92-byte type-2 response datagram.</summary>
        public byte[] EncodeResponse(WireGuardResponseMessage message)
        {
            ValidateField(message.UnencryptedEphemeral, WireGuardConstants.KeyLength, nameof(message.UnencryptedEphemeral));
            ValidateField(message.EncryptedNothing, RespEmptyLength, nameof(message.EncryptedNothing));
            ValidateField(message.Mac1, WireGuardConstants.MacLength, nameof(message.Mac1));
            ValidateField(message.Mac2, WireGuardConstants.MacLength, nameof(message.Mac2));

            byte[] buffer = new byte[WireGuardConstants.ResponseMessageLength];
            buffer[RespTypeOffset] = WireGuardConstants.MessageTypeResponse; // next 3 bytes stay zero (reserved)
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(RespSenderOffset, 4), message.SenderIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(RespReceiverOffset, 4), message.ReceiverIndex);
            message.UnencryptedEphemeral.CopyTo(buffer.AsSpan(RespEphemeralOffset));
            message.EncryptedNothing.CopyTo(buffer.AsSpan(RespEmptyOffset));
            message.Mac1.CopyTo(buffer.AsSpan(RespMac1Offset));
            message.Mac2.CopyTo(buffer.AsSpan(RespMac2Offset));
            return buffer;
        }

        /// <summary>
        /// Parses a 92-byte type-2 response datagram. Returns <c>false</c> (no exception) when the length or the
        /// type/reserved bytes are wrong.
        /// </summary>
        public bool TryDecodeResponse(ReadOnlySpan<byte> datagram, out WireGuardResponseMessage message)
        {
            message = null!;
            if (datagram.Length != WireGuardConstants.ResponseMessageLength) return false;
            if (datagram[RespTypeOffset] != WireGuardConstants.MessageTypeResponse) return false;
            if (datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0) return false;

            message = new WireGuardResponseMessage
            {
                SenderIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(RespSenderOffset, 4)),
                ReceiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram.Slice(RespReceiverOffset, 4)),
                UnencryptedEphemeral = datagram.Slice(RespEphemeralOffset, WireGuardConstants.KeyLength).ToArray(),
                EncryptedNothing = datagram.Slice(RespEmptyOffset, RespEmptyLength).ToArray(),
                Mac1 = datagram.Slice(RespMac1Offset, WireGuardConstants.MacLength).ToArray(),
                Mac2 = datagram.Slice(RespMac2Offset, WireGuardConstants.MacLength).ToArray(),
            };
            return true;
        }

        static void ValidateField(byte[] field, int expected, string name)
        {
            if (field is null) throw new ArgumentNullException(name);
            if (field.Length != expected) throw new ArgumentException($"{name} must be {expected} bytes (got {field.Length}).", name);
        }
    }
}
