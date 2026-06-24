using System.Text;
using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Meta
{
    /// <summary>
    /// Drives the tinc <b>meta-connection</b> over the TCP byte stream: the cleartext ID exchange, the SPTPS handshake
    /// (KEX → SIG → ACK, reusing phase-a <see cref="SptpsHandshake"/> + <see cref="SptpsRecordLayer"/>), and then
    /// SPTPS-framed request lines (each meta request is one application record of type 0). It is the client side of
    /// tinc's <c>protocol_auth.c</c> meta protocol; semantics (ACK / ADD_SUBNET / ADD_EDGE / REQ_KEY / ANS_KEY) are
    /// interpreted by the caller (<see cref="TincConnection"/>) — this type only sequences the handshake and the
    /// per-record I/O.
    /// </summary>
    public sealed class TincMetaConnection
    {
        readonly IByteStreamTransport _stream;
        readonly string _myName;
        readonly byte[] _myEd25519Seed;
        readonly byte[] _peerEd25519Public;
        readonly ILogger _logger;

        readonly SptpsRecordLayer _record = new();
        readonly List<byte> _inbound = new();
        readonly byte[] _readBuffer = new byte[8192];

        string? _peerName;
        SptpsHandshake? _handshake;

        /// <summary>Creates a meta-connection driver over an already-connected <paramref name="stream"/>.</summary>
        public TincMetaConnection(IByteStreamTransport stream, string myName, byte[] myEd25519Seed, byte[] peerEd25519Public, ILogger logger)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _myName = myName ?? throw new ArgumentNullException(nameof(myName));
            _myEd25519Seed = myEd25519Seed ?? throw new ArgumentNullException(nameof(myEd25519Seed));
            _peerEd25519Public = peerEd25519Public ?? throw new ArgumentNullException(nameof(peerEd25519Public));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>The peer node name learned from its ID line (available after <see cref="HandshakeAsync"/>).</summary>
        public string PeerName => _peerName ?? throw new InvalidOperationException("Handshake has not run yet.");

        /// <summary>
        /// Runs the cleartext ID exchange and the SPTPS meta handshake as the outgoing (initiator) side. On return the
        /// record layer is keyed; meta request lines flow via <see cref="SendRequestAsync"/> / <see cref="ReadRequestAsync"/>.
        /// </summary>
        public async Task HandshakeAsync(CancellationToken cancellationToken)
        {
            // 1) Send our ID (cleartext) and read the peer's ID line.
            byte[] idLine = TincMetaRequest.Id(_myName, TincDriverConstants.ProtocolMajor, TincDriverConstants.ProtocolMinor).ToBytes();
            await _stream.WriteAsync(idLine, cancellationToken).ConfigureAwait(false);

            string peerIdLine = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            TincMetaRequest peerId = TincMetaRequest.Parse(peerIdLine);
            _peerName = peerId.Arguments.Count > 0 ? peerId.Arguments[0] : throw new VpnConnectionException($"Malformed peer ID line: '{peerIdLine}'.");
            _logger.LogTrace("[tinc-meta] peer ID: {Line}", peerIdLine);

            // 2) SPTPS handshake (initiator). Label = "tinc TCP key expansion <me> <peer>" + NUL.
            byte[] label = SptpsHandshake.BuildMetaLabel(_myName, _peerName);
            _handshake = new SptpsHandshake(initiator: true, _myEd25519Seed, _peerEd25519Public, label);

            // initiator: send KEX (record seqno 0)
            byte[] kex = _handshake.CreateKex();
            await _stream.WriteAsync(_record.EncodeHandshake(kex), cancellationToken).ConfigureAwait(false);

            // read peer KEX
            (byte kexType, byte[] kexData) = await ReadRecordAsync(cancellationToken).ConfigureAwait(false);
            if (kexType != (byte)SptpsRecordType.Handshake) throw new VpnConnectionException("Expected a KEX handshake record.");
            _handshake.ConsumeKex(kexData);

            // send SIG (record seqno 1, still cleartext)
            byte[] sig = _handshake.CreateSig();
            await _stream.WriteAsync(_record.EncodeHandshake(sig), cancellationToken).ConfigureAwait(false);

            // read peer SIG and verify
            (byte sigType, byte[] sigData) = await ReadRecordAsync(cancellationToken).ConfigureAwait(false);
            if (sigType != (byte)SptpsRecordType.Handshake) throw new VpnConnectionException("Expected a SIG handshake record.");
            if (!_handshake.ConsumeSig(sigData)) throw new VpnConnectionException("tinc server SIG verification failed (wrong Ed25519 key?).");
            _logger.LogTrace("[tinc-meta] server SIG verified");

            // After receiving the peer SIG, tinc's SPTPS enables the OUT keys and the initiator sends an empty ACK
            // record (encrypted, record seqno 2), then waits for the peer's empty ACK record to enable the IN keys.
            _record.EnableEncryption(_handshake.OutCipherKey, _handshake.InCipherKey);
            await _stream.WriteAsync(_record.EncodeRecord((byte)SptpsRecordType.Handshake, ReadOnlySpan<byte>.Empty), cancellationToken).ConfigureAwait(false);

            (byte ackType, byte[] ackData) = await ReadRecordAsync(cancellationToken).ConfigureAwait(false);
            if (ackType != (byte)SptpsRecordType.Handshake || ackData.Length != 0)
                throw new VpnConnectionException($"Expected an empty ACK handshake record (got type {ackType}, {ackData.Length} bytes).");
            _logger.LogTrace("[tinc-meta] SPTPS handshake complete (keyed)");
        }

        /// <summary>Sends one meta request line as an SPTPS application record (type 0). Appends the trailing newline.</summary>
        public Task SendRequestAsync(TincMetaRequest request, CancellationToken cancellationToken)
        {
            byte[] line = request.ToBytes(); // includes the trailing '\n'
            byte[] frame = _record.EncodeRecord(0, line);
            return _stream.WriteAsync(frame, cancellationToken).AsTask();
        }

        /// <summary>
        /// Reads one application record (a meta request line) and parses it. Skips any control records (handshake /
        /// alert / close) by reading the next record. Returns null on a clean close (the peer closed the stream).
        /// </summary>
        public async Task<TincMetaRequest?> ReadRequestAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                (byte type, byte[] data) result;
                try { result = await ReadRecordAsync(cancellationToken).ConfigureAwait(false); }
                catch (EndOfStreamException) { return null; }

                if (result.type >= (byte)SptpsRecordType.Handshake) continue; // control record — ignore, read next
                string line = Encoding.ASCII.GetString(result.data).TrimEnd('\n');
                if (line.Length == 0) continue;
                return TincMetaRequest.Parse(line);
            }
        }

        // ---- record / line framing helpers ----

        async Task<(byte type, byte[] data)> ReadRecordAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                SptpsDecodeResult result = _record.TryDecodeRecord(_inbound.ToArray(), out byte type, out byte[] data, out int consumed);
                if (result == SptpsDecodeResult.Ok)
                {
                    _inbound.RemoveRange(0, consumed);
                    return (type, data);
                }
                if (result == SptpsDecodeResult.AuthFailed)
                    throw new VpnConnectionException("tinc meta record authentication failed (out of sync / wrong key).");
                await FillAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        async Task<string> ReadLineAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                int nl = _inbound.IndexOf((byte)'\n');
                if (nl >= 0)
                {
                    var sb = new StringBuilder(nl);
                    for (int i = 0; i < nl; i++) { byte b = _inbound[i]; if (b != (byte)'\r') sb.Append((char)b); }
                    _inbound.RemoveRange(0, nl + 1);
                    return sb.ToString();
                }
                await FillAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        async Task FillAsync(CancellationToken cancellationToken)
        {
            int read = await _stream.ReadAsync(_readBuffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0) throw new EndOfStreamException("tinc meta-connection closed by peer.");
            for (int i = 0; i < read; i++) _inbound.Add(_readBuffer[i]);
        }
    }
}
