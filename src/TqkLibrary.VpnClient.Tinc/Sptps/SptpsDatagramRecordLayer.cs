using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The SPTPS datagram (UDP) record layer used for the data plane. Unlike the TCP stream layer there is no length
    /// field; instead each datagram carries its 4-byte sequence number in the clear (it is needed as the cipher nonce
    /// and to survive reordering/loss). Wire form once keyed: <c>uint32 seqno(BE) || encrypt(seqno, type(1) || data)
    /// || tag(16)</c> — a fixed 21-byte overhead (<c>SPTPS_DATAGRAM_OVERHEAD</c>). Inbound records are checked against
    /// an <see cref="AntiReplayWindow"/> (reusing the shared Crypto primitive) to drop replays/old packets.
    /// </summary>
    public sealed class SptpsDatagramRecordLayer
    {
        const int SeqnoBytes = 4;
        const int TypeByte = 1;

        readonly TincChaChaPoly1305 _outCipher;
        readonly TincChaChaPoly1305 _inCipher;
        readonly AntiReplayWindow _replay = new AntiReplayWindow();
        ulong _outSeqno;

        /// <summary>Builds the data-plane layer from the directional keys derived by the SPTPS handshake.</summary>
        public SptpsDatagramRecordLayer(ReadOnlySpan<byte> outKey, ReadOnlySpan<byte> inKey)
        {
            _outCipher = new TincChaChaPoly1305(outKey);
            _inCipher = new TincChaChaPoly1305(inKey);
        }

        /// <summary>Seals one datagram record. Returns <c>seqno(4) || ciphertext || tag(16)</c>.</summary>
        public byte[] Encode(byte type, ReadOnlySpan<byte> data)
        {
            uint seqno = (uint)_outSeqno;
            byte[] plain = new byte[TypeByte + data.Length];
            plain[0] = type;
            data.CopyTo(plain.AsSpan(TypeByte));

            byte[] sealedBody = new byte[plain.Length + TincChaChaPoly1305.TagLength];
            _outCipher.Encrypt(_outSeqno, plain, sealedBody);
            _outSeqno++;

            byte[] frame = new byte[SeqnoBytes + sealedBody.Length];
            frame[0] = (byte)(seqno >> 24);
            frame[1] = (byte)(seqno >> 16);
            frame[2] = (byte)(seqno >> 8);
            frame[3] = (byte)seqno;
            sealedBody.CopyTo(frame.AsSpan(SeqnoBytes));
            return frame;
        }

        /// <summary>
        /// Opens one datagram record. Reads the plaintext seqno, decrypts under it and enforces the replay window.
        /// Returns <see cref="SptpsDecodeResult.Ok"/> with the type/data, or a failure reason.
        /// </summary>
        public SptpsDecodeResult Decode(ReadOnlySpan<byte> frame, out byte type, out byte[] data)
        {
            type = 0;
            data = Array.Empty<byte>();
            if (frame.Length < SeqnoBytes + TypeByte + TincChaChaPoly1305.TagLength)
                return SptpsDecodeResult.NeedMore;

            uint seqno = (uint)((frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3]);

            int bodyLen = frame.Length - SeqnoBytes;
            byte[] plain = new byte[bodyLen - TincChaChaPoly1305.TagLength];
            if (!_inCipher.Decrypt(seqno, frame.Slice(SeqnoBytes, bodyLen), plain))
                return SptpsDecodeResult.AuthFailed;

            // Replay window keyed on the 32-bit datagram seqno (matches tinc's s->replaywin). SPTPS numbers its first
            // record 0 whereas AntiReplayWindow reserves 0 (ESP/OpenVPN start at 1), so shift by +1. Commit only after
            // the AEAD tag has verified above.
            uint windowSeq = seqno + 1;
            if (!_replay.Check(windowSeq))
                return SptpsDecodeResult.AuthFailed;
            _replay.Commit(windowSeq);

            type = plain[0];
            data = plain.AsSpan(TypeByte).ToArray();
            return SptpsDecodeResult.Ok;
        }
    }
}
