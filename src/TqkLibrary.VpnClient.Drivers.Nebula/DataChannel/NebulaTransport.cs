using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Nebula.Packet;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;

namespace TqkLibrary.VpnClient.Drivers.Nebula.DataChannel
{
    /// <summary>
    /// The Nebula transport (data) channel for one established session, built on the AES-256-GCM transport keys produced
    /// by the Noise IX handshake's <c>Split</c>. <see cref="Seal"/> encrypts an outbound inner IP packet into a
    /// <c>Message</c> (type-1) datagram and <see cref="TryOpen"/> recovers one (dropping a bad tag, a replay or an
    /// out-of-window counter).
    /// <para>
    /// Wire layout (matching nebula's <c>connectionManager</c>/<c>outside.go</c>): the 16-byte header is the AEAD
    /// <b>associated data</b> (its <see cref="NebulaHeader.RemoteIndex"/> is the peer's session index — so the peer can
    /// route the datagram — and its <see cref="NebulaHeader.MessageCounter"/> is the per-session nonce). The AEAD nonce
    /// is <c>0^4 ‖ counter(8 BE)</c> (12 bytes, big-endian for AES-GCM). The ciphertext+tag follow the header.
    /// </para>
    /// <para>
    /// The send counter is a monotonic <c>u64</c> starting at 1 (counter 0 is reserved); the receiver runs a 64-packet
    /// sliding <see cref="NebulaReplayProtector"/> over the full 64-bit counter. Each peer seals with its
    /// <c>SendKey</c> and the peer's chosen index, opening with its <c>ReceiveKey</c> and its own index.
    /// </para>
    /// </summary>
    public sealed class NebulaTransport
    {
        readonly byte[] _sendKey;
        readonly byte[] _receiveKey;
        readonly uint _sendRemoteIndex;   // the peer's index — stamped onto datagrams we send so the peer can route them
        readonly uint _localIndex;        // our own index — datagrams we accept must carry this
        readonly IAeadCipher _cipher;
        readonly NebulaHeaderCodec _headerCodec = new();
        readonly NebulaReplayProtector _replay = new();
        readonly object _sync = new();

        ulong _sendCounter = 1;           // next counter to use; the first sealed packet is counter 1 (0 reserved)

        /// <summary>
        /// Creates a transport over the given keys. <paramref name="sendRemoteIndex"/> is the index the <b>peer</b>
        /// assigned to this session (its <c>ResponderIndex</c>, echoed on every datagram we send so it can find the
        /// session); <paramref name="localIndex"/> is <b>our</b> index (datagrams must address it to be accepted).
        /// <paramref name="cipher"/> defaults to AES-256-GCM — Nebula's data-channel AEAD.
        /// </summary>
        public NebulaTransport(byte[] sendKey, byte[] receiveKey, uint sendRemoteIndex, uint localIndex, IAeadCipher? cipher = null)
        {
            if (sendKey is null || sendKey.Length != 32) throw new ArgumentException("SendKey must be 32 bytes.", nameof(sendKey));
            if (receiveKey is null || receiveKey.Length != 32) throw new ArgumentException("ReceiveKey must be 32 bytes.", nameof(receiveKey));
            _sendKey = (byte[])sendKey.Clone();
            _receiveKey = (byte[])receiveKey.Clone();
            _sendRemoteIndex = sendRemoteIndex;
            _localIndex = localIndex;
            _cipher = cipher ?? new AesGcmCipher(32);
        }

        /// <summary>The number of packets sealed so far (also the next counter minus one).</summary>
        public ulong SentPacketCount { get { lock (_sync) return _sendCounter - 1; } }

        /// <summary>The highest 64-bit counter accepted on the receive side.</summary>
        public ulong HighestReceivedCounter { get { lock (_sync) return _replay.Highest; } }

        /// <summary>
        /// Seals an inner IP packet <paramref name="plaintext"/> into a <c>Message</c> (type-1) datagram
        /// (<c>header(16) ‖ ciphertext ‖ tag(16)</c>). The header is the AEAD associated data and carries the peer's
        /// session index and the per-session counter. Throws when the counter would overflow (rekey required first).
        /// </summary>
        public byte[] Seal(ReadOnlySpan<byte> plaintext)
        {
            ulong counter;
            lock (_sync)
            {
                if (_sendCounter == 0UL)
                    throw new InvalidOperationException("Nebula message counter overflowed; a re-handshake is required before sealing more packets.");
                counter = _sendCounter;
                _sendCounter = unchecked(_sendCounter + 1UL);
            }

            var header = new NebulaHeader
            {
                Version = 1,
                Type = NebulaMessageType.Message,
                SubType = (byte)NebulaMessageSubType.None,
                Reserved = 0,
                RemoteIndex = _sendRemoteIndex,
                MessageCounter = counter,
            };
            byte[] aad = _headerCodec.Encode(header); // the 16-byte header is the AEAD associated data

            byte[] wire = new byte[NebulaHeader.Size + plaintext.Length + NebulaDriverConstants.TagLength];
            aad.CopyTo(wire.AsSpan(0));

            Span<byte> nonce = stackalloc byte[NebulaDriverConstants.NonceLength];
            WriteNonce(nonce, counter);

            _cipher.Seal(_sendKey, nonce, plaintext, aad,
                wire.AsSpan(NebulaHeader.Size, plaintext.Length),
                wire.AsSpan(NebulaHeader.Size + plaintext.Length, NebulaDriverConstants.TagLength));
            return wire;
        }

        /// <summary>
        /// Opens an incoming <c>Message</c> (type-1) datagram into the inner IP packet. Returns <c>false</c> (no
        /// exception) if it is not a message for this session, is truncated, is addressed to a different index, fails
        /// the AEAD tag, or replays / falls outside the anti-replay window.
        /// </summary>
        public bool TryOpen(ReadOnlySpan<byte> datagram, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (!_headerCodec.TryDecode(datagram, out NebulaHeader header)) return false;
            if (header.Type != NebulaMessageType.Message) return false;
            if (header.RemoteIndex != _localIndex) return false;
            if (datagram.Length < NebulaHeader.Size + NebulaDriverConstants.TagLength) return false;

            ulong counter = header.MessageCounter;
            lock (_sync) { if (!_replay.Check(counter)) return false; }

            Span<byte> nonce = stackalloc byte[NebulaDriverConstants.NonceLength];
            WriteNonce(nonce, counter);

            // The associated data is the exact 16 header bytes on the wire (re-encoding would match, but slicing avoids
            // trusting the decode round-trip).
            ReadOnlySpan<byte> aad = datagram.Slice(0, NebulaHeader.Size);
            int cipherTextLength = datagram.Length - NebulaHeader.Size - NebulaDriverConstants.TagLength;
            byte[] pt = new byte[cipherTextLength];
            bool ok = _cipher.Open(
                _receiveKey,
                nonce,
                datagram.Slice(NebulaHeader.Size, cipherTextLength),
                datagram.Slice(NebulaHeader.Size + cipherTextLength, NebulaDriverConstants.TagLength),
                aad,
                pt);
            if (!ok) return false;

            lock (_sync) _replay.Commit(counter);
            plaintext = pt;
            return true;
        }

        // nonce = 4 zero bytes followed by the 8-byte big-endian message counter (AES-GCM uses a big-endian nonce; the
        // counter occupies the last 8 of the 12 bytes). Verified live: nebula accepts/decrypts this layout.
        static void WriteNonce(Span<byte> nonce, ulong counter)
        {
            nonce.Slice(0, 4).Clear();
            for (int i = 0; i < 8; i++) nonce[11 - i] = (byte)(counter >> (8 * i));
        }
    }
}
