using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// A DTLS 1.2 client datagram transport: an <see cref="IDatagramTransport"/> that wraps an <b>inner</b>
    /// <see cref="IDatagramTransport"/> (the plaintext UDP pipe), runs a BouncyCastle DTLS handshake over it on
    /// <see cref="ConnectAsync"/>, then encrypts each <see cref="SendAsync"/> and decrypts each <see cref="ReceiveAsync"/>
    /// as a single DTLS record. Boundaries are preserved (one app datagram = one DTLS record = one UDP datagram), so this
    /// is a drop-in replacement for a raw UDP transport wherever a confidential datagram pipe is needed — first consumer
    /// is the OpenConnect (V.5) DTLS data path.
    /// <para>
    /// <b>Why BouncyCastle:</b> the BCL <c>SslStream</c> implements TLS only, not DTLS, on every supported target
    /// framework, so the handshake and record layer run through <see cref="DtlsClientProtocol"/> on both
    /// <c>netstandard2.0</c> and <c>net8.0</c>.
    /// </para>
    /// <para>
    /// <b>Threading:</b> BouncyCastle's <see cref="DtlsTransport"/> is synchronous. The blocking handshake runs once on a
    /// thread-pool thread inside <see cref="ConnectAsync"/>; afterwards each send/receive offloads its single blocking
    /// call. BouncyCastle's record layer tolerates one concurrent sender and one concurrent receiver, matching the usual
    /// "one write loop + one read loop" driver model; it is not safe to call <see cref="SendAsync"/> (or
    /// <see cref="ReceiveAsync"/>) from two threads at once, exactly like a raw socket.
    /// </para>
    /// </summary>
    public sealed class DtlsDatagramTransport : IDatagramTransport
    {
        readonly IDatagramTransport _inner;
        readonly DtlsServerCertificateValidationCallback? _certificateValidationCallback;
        readonly DtlsResumptionParameters? _resumption;
        readonly bool _ownsInner;

        BouncyCastleDatagramBridge? _bridge;
        DtlsTransport? _dtls;
        int _disposed;

        /// <summary>
        /// Wraps <paramref name="inner"/> (the plaintext UDP pipe) in DTLS. <paramref name="certificateValidationCallback"/>
        /// validates the server certificate during the handshake (null = accept any). When <paramref name="ownsInner"/> is
        /// true (the default) disposing this transport also disposes the inner pipe. When <paramref name="resumption"/> is
        /// supplied the client runs the legacy AnyConnect <b>abbreviated</b> handshake — offering the gateway's session id
        /// + pre-shared master secret (ocserv <c>dtls-legacy</c>) — instead of a full handshake; null = full handshake
        /// (offline loopback / non-legacy gateways).
        /// </summary>
        public DtlsDatagramTransport(IDatagramTransport inner,
            DtlsServerCertificateValidationCallback? certificateValidationCallback = null, bool ownsInner = true,
            DtlsResumptionParameters? resumption = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _certificateValidationCallback = certificateValidationCallback;
            _resumption = resumption;
            _ownsInner = ownsInner;
        }

        /// <summary>The negotiated DTLS receive limit (max plaintext bytes per <see cref="ReceiveAsync"/>); 0 until connected.</summary>
        public int ReceiveLimit => _dtls?.GetReceiveLimit() ?? 0;

        /// <summary>The negotiated DTLS send limit (max plaintext bytes per <see cref="SendAsync"/>); 0 until connected.</summary>
        public int SendLimit => _dtls?.GetSendLimit() ?? 0;

        /// <summary>Connects the inner pipe (if needed) then runs the DTLS 1.2 client handshake over it.</summary>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            if (_dtls is not null) throw new InvalidOperationException("The DTLS transport is already connected.");

            await _inner.ConnectAsync(cancellationToken).ConfigureAwait(false);
            var bridge = new BouncyCastleDatagramBridge(_inner);
            _bridge = bridge;

            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new DefaultDtlsClient(crypto, _certificateValidationCallback, _resumption);
            var protocol = new DtlsClientProtocol();

            try
            {
                // The handshake is blocking (its retransmit timer drives the bridge's waitMillis Receive); run it off the
                // caller's thread and let cancellation abort it by closing the bridge so the blocking Receive returns.
                using (cancellationToken.Register(static b => ((BouncyCastleDatagramBridge)b!).Close(), bridge))
                {
                    _dtls = await Task.Run(() => protocol.Connect(client, bridge), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                bridge.Close();
                _bridge = null;
                throw;
            }
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            DtlsTransport dtls = _dtls ?? throw new InvalidOperationException("The DTLS transport is not connected.");
            cancellationToken.ThrowIfCancellationRequested();
            // Receive blocks up to waitMillis then returns -1 (timeout). Loop with a short wait so cancellation is honoured
            // promptly without busy-spinning; -1 simply means "no record yet".
            return await Task.Run(() =>
            {
                byte[] temp = new byte[Math.Max(buffer.Length, dtls.GetReceiveLimit())];
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int read = dtls.Receive(temp, 0, temp.Length, 200);
                    if (read < 0) continue; // timeout — keep waiting (UDP/DTLS has no read deadline of its own)
                    int n = Math.Min(read, buffer.Length);
                    temp.AsSpan(0, n).CopyTo(buffer.Span);
                    return n;
                }
            }, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        {
            DtlsTransport dtls = _dtls ?? throw new InvalidOperationException("The DTLS transport is not connected.");
            cancellationToken.ThrowIfCancellationRequested();
            byte[] copy = datagram.ToArray(); // BouncyCastle Send takes a byte[]+offset+len; copy out of the Memory
            await Task.Run(() => dtls.Send(copy, 0, copy.Length), cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { _dtls?.Close(); } catch { } // sends a close_notify alert (best-effort)
            _bridge?.Close();
            if (_ownsInner)
                await _inner.DisposeAsync().ConfigureAwait(false);
        }

        void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(DtlsDatagramTransport));
        }
    }
}
