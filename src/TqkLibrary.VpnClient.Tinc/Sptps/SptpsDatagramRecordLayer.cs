using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// The SPTPS datagram (UDP) record layer, modelling tinc's <c>send_record_priv_datagram</c> /
    /// <c>sptps_receive_data_datagram</c>. Unlike the TCP stream layer there is no length field; instead each datagram
    /// carries its 4-byte sequence number in the clear (it is the cipher nonce and survives reordering/loss).
    /// <para>
    /// <b>Plaintext (handshake) records</b> — before <see cref="EnableEncryption"/>: <c>seqno(4 BE) ‖ type(1) ‖ data</c>.
    /// These carry the KEX/SIG/ACK exchange and are sent in order (the receiver enforces <c>seqno == inseqno</c>).
    /// <b>Encrypted (data) records</b> — once keyed: <c>seqno(4 BE) ‖ encrypt(seqno, type(1) ‖ data) ‖ tag(16)</c>, a
    /// fixed 21-byte overhead (<c>SPTPS_DATAGRAM_OVERHEAD</c>), checked against an <see cref="AntiReplayWindow"/>.
    /// </para>
    /// <para>
    /// The send and receive sequence numbers are <b>shared</b> across the handshake and data phases (tinc's
    /// <c>outseqno</c>/<c>inseqno</c>): the handshake records advance them, so the first encrypted data record's nonce
    /// is the post-handshake seqno — exactly as the TCP <see cref="SptpsRecordLayer"/>.
    /// </para>
    /// </summary>
    public sealed class SptpsDatagramRecordLayer
    {
        const int SeqnoBytes = 4;
        const int TypeByte = 1;

        readonly AntiReplayWindow _replay = new AntiReplayWindow();
        TincChaChaPoly1305? _outCipher;
        TincChaChaPoly1305? _inCipher;
        ulong _outSeqno;
        uint _inSeqno; // strict in-order counter used only for plaintext handshake records

        /// <summary>
        /// Creates an unkeyed datagram layer (for the handshake phase). Call <see cref="EnableEncryption"/> once the
        /// SPTPS keys are derived to switch subsequent records to the encrypted (data) framing.
        /// </summary>
        public SptpsDatagramRecordLayer()
        {
        }

        /// <summary>
        /// Creates a datagram layer that is already keyed (the handshake happened elsewhere). The send/receive seqno
        /// continue from <paramref name="initialSeqno"/> so they stay in lockstep with the peer (the handshake records
        /// already consumed earlier seqnos). Used when the SPTPS key exchange is carried over a side channel (tinc's
        /// data-plane handshake runs over the meta-connection via REQ_KEY/ANS_KEY, then data flows over UDP).
        /// </summary>
        public SptpsDatagramRecordLayer(ReadOnlySpan<byte> outKey, ReadOnlySpan<byte> inKey, uint initialSeqno = 0)
        {
            _outCipher = new TincChaChaPoly1305(outKey);
            _inCipher = new TincChaChaPoly1305(inKey);
            _outSeqno = initialSeqno;
        }

        /// <summary>True once <see cref="EnableEncryption"/> has installed the cipher keys.</summary>
        public bool Encrypted => _outCipher is not null;

        /// <summary>The next out-seqno that will be used (also the count of records sent so far).</summary>
        public ulong OutSeqno => _outSeqno;

        /// <summary>Installs the directional cipher keys and switches subsequent records to encrypted (data) framing.</summary>
        public void EnableEncryption(ReadOnlySpan<byte> outKey, ReadOnlySpan<byte> inKey)
        {
            _outCipher = new TincChaChaPoly1305(outKey);
            _inCipher = new TincChaChaPoly1305(inKey);
        }

        /// <summary>
        /// Encodes one plaintext handshake record (<c>seqno(4) ‖ type(1) ‖ data</c>) and advances the out-seqno. Used
        /// for KEX/SIG/ACK before encryption is enabled.
        /// </summary>
        public byte[] EncodeHandshake(byte type, ReadOnlySpan<byte> data)
        {
            uint seqno = (uint)_outSeqno;
            _outSeqno++;
            byte[] frame = new byte[SeqnoBytes + TypeByte + data.Length];
            WriteSeqno(frame, seqno);
            frame[SeqnoBytes] = type;
            data.CopyTo(frame.AsSpan(SeqnoBytes + TypeByte));
            return frame;
        }

        /// <summary>
        /// Decodes one inbound plaintext handshake record (<c>seqno(4) ‖ type(1) ‖ data</c>), enforcing the strict
        /// in-order seqno (tinc rejects an out-of-order handshake datagram). Advances the in-seqno on success.
        /// </summary>
        public SptpsDecodeResult DecodeHandshake(ReadOnlySpan<byte> frame, out byte type, out byte[] data)
        {
            type = 0;
            data = Array.Empty<byte>();
            if (frame.Length < SeqnoBytes + TypeByte) return SptpsDecodeResult.NeedMore;

            uint seqno = (uint)((frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3]);
            if (seqno != _inSeqno) return SptpsDecodeResult.AuthFailed; // strict in-order handshake
            _inSeqno = seqno + 1;

            type = frame[SeqnoBytes];
            data = frame.Slice(SeqnoBytes + TypeByte).ToArray();
            return SptpsDecodeResult.Ok;
        }

        /// <summary>Seals one encrypted data record. Returns <c>seqno(4) ‖ ciphertext ‖ tag(16)</c>.</summary>
        public byte[] Encode(byte type, ReadOnlySpan<byte> data)
        {
            if (_outCipher is null) throw new InvalidOperationException("Datagram layer is not keyed yet.");
            uint seqno = (uint)_outSeqno;
            byte[] plain = new byte[TypeByte + data.Length];
            plain[0] = type;
            data.CopyTo(plain.AsSpan(TypeByte));

            byte[] sealedBody = new byte[plain.Length + TincChaChaPoly1305.TagLength];
            _outCipher.Encrypt(_outSeqno, plain, sealedBody);
            _outSeqno++;

            byte[] frame = new byte[SeqnoBytes + sealedBody.Length];
            WriteSeqno(frame, seqno);
            sealedBody.CopyTo(frame.AsSpan(SeqnoBytes));
            return frame;
        }

        /// <summary>
        /// Opens one encrypted data record. Reads the plaintext seqno, decrypts under it and enforces the replay window.
        /// Returns <see cref="SptpsDecodeResult.Ok"/> with the type/data, or a failure reason.
        /// </summary>
        public SptpsDecodeResult Decode(ReadOnlySpan<byte> frame, out byte type, out byte[] data)
        {
            type = 0;
            data = Array.Empty<byte>();
            if (_inCipher is null) throw new InvalidOperationException("Datagram layer is not keyed yet.");
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

        static void WriteSeqno(byte[] frame, uint seqno)
        {
            frame[0] = (byte)(seqno >> 24);
            frame[1] = (byte)(seqno >> 16);
            frame[2] = (byte)(seqno >> 8);
            frame[3] = (byte)seqno;
        }
    }
}
