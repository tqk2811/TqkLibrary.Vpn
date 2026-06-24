using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    // SptpsDecodeResult lives in Sptps.Enums.
    /// <summary>
    /// The SPTPS stream (TCP) record layer: frames and, once keyed, encrypts/authenticates records over a TCP
    /// meta-connection. Wire form is <c>uint16 length(BE) || type(1) || data</c> while in the clear (handshake), and
    /// <c>uint16 length(BE) || encrypt(seqno, type(1) || data) || tag(16)</c> once <see cref="EnableEncryption"/> has
    /// installed the directional ChaCha-Poly1305 keys. The plaintext <c>length</c> equals the data length only (it
    /// excludes the type byte and the tag), matching tinc's <c>send_record_priv</c>. Send and receive sequence numbers
    /// are independent and start at 0; <b>every</b> record consumes exactly one seqno — including the cleartext KEX/SIG
    /// handshake records sent before <see cref="EnableEncryption"/> — so the first encrypted record's AEAD nonce is the
    /// post-handshake seqno (2 after KEX+SIG), exactly as tinc's <c>s->outseqno++</c> in <c>send_record_priv</c>.
    /// </summary>
    public sealed class SptpsRecordLayer
    {
        const int LengthPrefix = 2;
        const int TypeByte = 1;

        TincChaChaPoly1305? _outCipher;
        TincChaChaPoly1305? _inCipher;
        ulong _outSeqno;
        ulong _inSeqno;

        /// <summary>True once <see cref="EnableEncryption"/> has been called (records are now sealed).</summary>
        public bool Encrypted => _outCipher is not null;

        /// <summary>Installs the directional cipher keys and switches subsequent records to encrypted framing.</summary>
        public void EnableEncryption(ReadOnlySpan<byte> outKey, ReadOnlySpan<byte> inKey)
        {
            _outCipher = new TincChaChaPoly1305(outKey);
            _inCipher = new TincChaChaPoly1305(inKey);
        }

        /// <summary>
        /// Encodes one record to send. Before encryption is enabled the body is in the clear (used for KEX/SIG
        /// handshake records); afterwards the type+data are sealed under the next out-seqno.
        /// </summary>
        public byte[] EncodeRecord(byte type, ReadOnlySpan<byte> data)
        {
            ushort len = checked((ushort)data.Length);
            // tinc's send_record_priv consumes one out-seqno for EVERY record, including the cleartext KEX/SIG
            // handshake records sent before encryption is enabled (the seqno is the AEAD nonce once keyed). So the
            // first encrypted record is not seqno 0 — the handshake records already advanced it. Increment here
            // unconditionally to stay in lockstep with the peer's nonce counter (validated live vs tincd 1.1pre18).
            ulong seqno = _outSeqno++;
            if (_outCipher is null)
            {
                byte[] frame = new byte[LengthPrefix + TypeByte + data.Length];
                WriteLength(frame, len);
                frame[2] = type;
                data.CopyTo(frame.AsSpan(LengthPrefix + TypeByte));
                return frame;
            }
            else
            {
                // Seal (type || data); ciphertext length = (1 + data) + tag.
                byte[] plain = new byte[TypeByte + data.Length];
                plain[0] = type;
                data.CopyTo(plain.AsSpan(TypeByte));
                byte[] sealedBody = new byte[plain.Length + TincChaChaPoly1305.TagLength];
                _outCipher.Encrypt(seqno, plain, sealedBody);

                byte[] frame = new byte[LengthPrefix + sealedBody.Length];
                WriteLength(frame, len); // length = data length only (excludes type and tag)
                sealedBody.CopyTo(frame.AsSpan(LengthPrefix));
                return frame;
            }
        }

        /// <summary>Encodes a handshake record (<see cref="SptpsRecordType.Handshake"/>) with the given payload.</summary>
        public byte[] EncodeHandshake(ReadOnlySpan<byte> data) => EncodeRecord((byte)SptpsRecordType.Handshake, data);

        /// <summary>
        /// Tries to decode one full record from the front of <paramref name="buffer"/>. On success sets
        /// <paramref name="type"/>/<paramref name="data"/>, advances <paramref name="consumed"/> past the record and
        /// returns <see cref="SptpsDecodeResult.Ok"/>. Returns <see cref="SptpsDecodeResult.NeedMore"/> if the buffer
        /// does not yet hold a whole record, or <see cref="SptpsDecodeResult.AuthFailed"/> if decryption fails.
        /// </summary>
        public SptpsDecodeResult TryDecodeRecord(ReadOnlySpan<byte> buffer, out byte type, out byte[] data, out int consumed)
        {
            type = 0;
            data = Array.Empty<byte>();
            consumed = 0;

            if (buffer.Length < LengthPrefix) return SptpsDecodeResult.NeedMore;
            int dataLen = (buffer[0] << 8) | buffer[1];

            if (_inCipher is null)
            {
                int total = LengthPrefix + TypeByte + dataLen;
                if (buffer.Length < total) return SptpsDecodeResult.NeedMore;
                type = buffer[LengthPrefix];
                data = buffer.Slice(LengthPrefix + TypeByte, dataLen).ToArray();
                consumed = total;
                // Cleartext handshake record still consumes one in-seqno so the first encrypted record decrypts
                // under the correct nonce (the peer counted these records too — see EncodeRecord).
                _inSeqno++;
                return SptpsDecodeResult.Ok;
            }
            else
            {
                // Encrypted body = (type + data) + tag = dataLen + 1 + 16.
                int bodyLen = TypeByte + dataLen + TincChaChaPoly1305.TagLength;
                int total = LengthPrefix + bodyLen;
                if (buffer.Length < total) return SptpsDecodeResult.NeedMore;

                byte[] plain = new byte[TypeByte + dataLen];
                if (!_inCipher.Decrypt(_inSeqno, buffer.Slice(LengthPrefix, bodyLen), plain))
                    return SptpsDecodeResult.AuthFailed;
                _inSeqno++;
                type = plain[0];
                data = plain.AsSpan(TypeByte).ToArray();
                consumed = total;
                return SptpsDecodeResult.Ok;
            }
        }

        static void WriteLength(byte[] frame, ushort len)
        {
            frame[0] = (byte)(len >> 8);
            frame[1] = (byte)(len & 0xFF);
        }
    }
}
