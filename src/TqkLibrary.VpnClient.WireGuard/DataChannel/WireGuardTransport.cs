using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.WireGuard.DataChannel
{
    /// <summary>
    /// The WireGuard transport (data) channel for one established session (whitepaper §5.4.6), built on the
    /// <see cref="WireGuardTransportKeys"/> produced by the handshake's <c>Split</c>. <see cref="Seal"/> encrypts an
    /// outbound inner packet into a type-4 datagram and <see cref="TryOpen"/> recovers one (dropping a bad tag, a
    /// replay, or an out-of-window counter). A <see cref="Keepalive"/> is a sealed datagram with an empty payload.
    /// <para>
    /// Each peer seals with <see cref="WireGuardTransportKeys.SendKey"/> and the peer's chosen <i>receiver index</i>
    /// (the sender index that peer advertised in the handshake) so the remote can look the session up; it opens with
    /// <see cref="WireGuardTransportKeys.ReceiveKey"/> and its own index. The AEAD is ChaCha20-Poly1305 (RFC 8439,
    /// reused from <see cref="ChaCha20Poly1305Cipher"/>) with nonce = <c>0^4 ‖ counter(8 LE)</c> and <b>empty</b> AAD.
    /// </para>
    /// <para>
    /// The send counter is a monotonic <c>u64</c> starting at 0; it must never repeat for a key, so overflow throws
    /// (a rekey must replace the transport first — V3.e). The receiver runs a 64-packet sliding
    /// <see cref="WireGuardReplayProtector"/> over the full 64-bit counter.
    /// </para>
    /// </summary>
    public sealed class WireGuardTransport
    {
        readonly byte[] _sendKey;
        readonly byte[] _receiveKey;
        readonly uint _sendReceiverIndex;   // the peer's index — stamped onto datagrams we send, so the peer can route them
        readonly uint _localReceiverIndex;  // our own index — datagrams we accept must carry this
        readonly IAeadCipher _cipher;
        readonly WireGuardDataCodec _codec;
        readonly WireGuardReplayProtector _replay = new();
        readonly object _sync = new();

        ulong _sendCounter;                 // next counter to use; the first sealed packet is counter 0
        bool _sendStarted;                  // distinguishes "no packet sealed yet" from "counter wrapped to 0"

        /// <summary>
        /// Creates a transport over <paramref name="keys"/>. <paramref name="sendReceiverIndex"/> is the index the
        /// <b>peer</b> assigned to this session (echoed on every datagram we send so it can find the session);
        /// <paramref name="localReceiverIndex"/> is <b>our</b> index (datagrams must address it to be accepted).
        /// <paramref name="cipher"/> defaults to ChaCha20-Poly1305 — WireGuard's only data-channel AEAD.
        /// </summary>
        public WireGuardTransport(WireGuardTransportKeys keys, uint sendReceiverIndex, uint localReceiverIndex, IAeadCipher? cipher = null)
        {
            if (keys is null) throw new ArgumentNullException(nameof(keys));
            if (keys.SendKey is null || keys.SendKey.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("SendKey must be 32 bytes.", nameof(keys));
            if (keys.ReceiveKey is null || keys.ReceiveKey.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("ReceiveKey must be 32 bytes.", nameof(keys));
            _sendKey = (byte[])keys.SendKey.Clone();
            _receiveKey = (byte[])keys.ReceiveKey.Clone();
            _sendReceiverIndex = sendReceiverIndex;
            _localReceiverIndex = localReceiverIndex;
            _cipher = cipher ?? new ChaCha20Poly1305Cipher();
            _codec = new WireGuardDataCodec();
        }

        /// <summary>The number of packets sealed so far (also the next counter to use).</summary>
        public ulong SentPacketCount { get { lock (_sync) return _sendCounter; } }

        /// <summary>The highest 64-bit counter accepted on the receive side.</summary>
        public ulong HighestReceivedCounter { get { lock (_sync) return _replay.Highest; } }

        /// <summary>
        /// Seals an inner packet <paramref name="plaintext"/> into a type-4 transport datagram
        /// (<c>type|reserved|receiver|counter|ciphertext‖tag</c>). Pass an empty span to build a keepalive
        /// (see <see cref="Keepalive"/>). Throws when the send counter would overflow (rekey required first).
        /// </summary>
        public byte[] Seal(ReadOnlySpan<byte> plaintext)
        {
            ulong counter;
            lock (_sync)
            {
                if (_sendStarted && _sendCounter == 0UL)
                    throw new InvalidOperationException("WireGuard transport counter overflowed; a rekey is required before sealing more packets.");
                counter = _sendCounter;
                _sendCounter = unchecked(_sendCounter + 1UL);
                _sendStarted = true;
            }

            byte[] wire = new byte[WireGuardDataCodec.HeaderLength + plaintext.Length + WireGuardConstants.TagLength];
            _codec.WriteHeader(wire, _sendReceiverIndex, counter);

            Span<byte> nonce = stackalloc byte[WireGuardDataCodec.NonceLength];
            _codec.WriteNonce(nonce, counter);

            // ciphertext sits right after the header; the 16-byte tag follows it. AAD is empty (WireGuard convention).
            _cipher.Seal(_sendKey, nonce, plaintext, ReadOnlySpan<byte>.Empty,
                wire.AsSpan(WireGuardDataCodec.HeaderLength, plaintext.Length),
                wire.AsSpan(WireGuardDataCodec.HeaderLength + plaintext.Length, WireGuardConstants.TagLength));
            return wire;
        }

        /// <summary>Builds a keepalive datagram: a sealed type-4 message with an empty payload (whitepaper §5.4.7).</summary>
        public byte[] Keepalive() => Seal(ReadOnlySpan<byte>.Empty);

        /// <summary>
        /// Opens an incoming type-4 transport datagram into the inner packet. Returns <c>false</c> (no exception) if it
        /// is not a transport-data message, is truncated, is addressed to a different receiver index, fails the AEAD
        /// tag, or replays/falls outside the anti-replay window. A keepalive opens to an empty (zero-length) packet —
        /// callers distinguish it by <c>plaintext.Length == 0</c> and do not forward it.
        /// </summary>
        public bool TryOpen(ReadOnlySpan<byte> datagram, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (!_codec.TryReadHeader(datagram, out uint receiverIndex, out ulong counter)) return false;
            if (receiverIndex != _localReceiverIndex) return false;

            lock (_sync) { if (!_replay.Check(counter)) return false; }

            Span<byte> nonce = stackalloc byte[WireGuardDataCodec.NonceLength];
            _codec.WriteNonce(nonce, counter);

            int cipherTextLength = datagram.Length - WireGuardDataCodec.HeaderLength - WireGuardConstants.TagLength;
            byte[] pt = new byte[cipherTextLength];
            bool ok = _cipher.Open(
                _receiveKey,
                nonce,
                datagram.Slice(WireGuardDataCodec.HeaderLength, cipherTextLength),
                datagram.Slice(WireGuardDataCodec.HeaderLength + cipherTextLength, WireGuardConstants.TagLength),
                ReadOnlySpan<byte>.Empty,
                pt);
            if (!ok) return false;

            lock (_sync) _replay.Commit(counter);
            plaintext = pt;
            return true;
        }
    }
}
