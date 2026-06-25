using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Transport.Tls
{
    /// <summary>
    /// A TLS 1.2 client byte stream backed by <b>BouncyCastle</b> (<see cref="TlsClientProtocol"/>) instead of the BCL
    /// <see cref="SslStream"/>. It exists for one reason the SslStream-based <see cref="TlsByteStream"/> cannot serve: it
    /// exposes an <b>RFC 5705 keying-material exporter</b> (<see cref="ExportKeyingMaterial"/>) over the finished TLS
    /// session — <see cref="SslStream"/> has no such API on <c>netstandard2.0</c>/<c>net8.0</c>. The first consumer is the
    /// OpenConnect (V.5) <b>DTLS 1.2 PSK</b> data path, whose 32-byte pre-shared key is exported from the CSTP
    /// control-channel TLS session (label <c>"EXPORTER-openconnect-psk"</c>, empty context).
    /// <para>
    /// It is otherwise a drop-in <see cref="ITlsByteStream"/>: it wraps a <see cref="TcpByteStream"/>, runs the client
    /// handshake (accept-any cert by default, captured into <see cref="RemoteCertificate"/>; an optional callback may
    /// reject), and reads/writes application data. SSTP/SoftEther keep using the SslStream <see cref="TlsByteStream"/> —
    /// only a caller that needs the exporter wires this one, so the live TLS data paths are unaffected.
    /// </para>
    /// <para>
    /// <b>Threading:</b> BouncyCastle's <see cref="TlsClientProtocol"/> drives a synchronous record layer over the inner
    /// <see cref="NetworkStream"/>. The blocking handshake runs once on a thread-pool thread inside
    /// <see cref="ConnectAsync"/>; afterwards each read/write offloads its single blocking call through the protocol's
    /// application-data <see cref="System.IO.Stream"/> (its record layer tolerates one concurrent reader and one
    /// concurrent writer — the usual read-loop + write-loop driver model).
    /// </para>
    /// </summary>
    public sealed class BouncyCastleTlsByteStream : ITlsByteStream, ITlsKeyingMaterialExporter, IDisposable
    {
        readonly TcpByteStream _tcp;
        readonly string _host;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly List<KeyingMaterialRequest> _pendingExports = new();

        TlsClientProtocol? _protocol;
        Stream? _appData; // protocol.Stream — the decrypted application-data pipe
        ExporterTlsClient? _client;

        /// <summary>
        /// Creates a BouncyCastle TLS byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).
        /// See the type summary for the certificate-validation semantics (accept-any by default; the cert is captured
        /// into <see cref="RemoteCertificate"/> either way). <paramref name="addressFamilyPreference"/> selects IPv4/IPv6
        /// for the inner TCP connection; <paramref name="hostResolver"/> performs the name→address lookup (default DNS).
        /// </summary>
        public BouncyCastleTlsByteStream(string host, int port = 443,
            RemoteCertificateValidationCallback? certificateValidationCallback = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(host, port, addressFamilyPreference, hostResolver);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <summary>
        /// Creates a BouncyCastle TLS byte stream over an already-resolved <paramref name="remote"/> endpoint, keeping
        /// <paramref name="host"/> as the TLS TargetHost (SNI). Used when the caller resolves the address itself (e.g. to
        /// correlate a parallel DTLS path).
        /// </summary>
        public BouncyCastleTlsByteStream(string host, IPEndPoint remote,
            RemoteCertificateValidationCallback? certificateValidationCallback = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(remote);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <inheritdoc/>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <summary>
        /// Registers an RFC 5705 keying-material export to be computed <b>during</b> the handshake (before
        /// <see cref="ConnectAsync"/>). BouncyCastle clears the TLS master secret as soon as the handshake completes, so
        /// any export must be captured while it is still alive; this queues the request and <see cref="ConnectAsync"/>
        /// fulfils it at handshake-complete, caching the bytes for <see cref="ExportKeyingMaterial"/> to return. The
        /// OpenConnect DTLS-PSK path registers its single export (label <c>"EXPORTER-openconnect-psk"</c>, empty context,
        /// 32 bytes) up front.
        /// </summary>
        public void RequestKeyingMaterialExport(string label, ReadOnlySpan<byte> context, int length)
        {
            if (_protocol is not null) throw new InvalidOperationException("Keying-material exports must be requested before connecting.");
            _pendingExports.Add(new KeyingMaterialRequest(label, context.ToArray(), length));
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            await _tcp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new ExporterTlsClient(crypto, _host, _certificateValidationCallback,
                cert => RemoteCertificate = cert, _pendingExports);
            var protocol = new TlsClientProtocol(_tcp.Stream);

            try
            {
                // The BC handshake is blocking (it reads/writes the inner NetworkStream inline); run it off the caller's
                // thread and abort it by disposing the inner socket so the blocking read returns.
                using (cancellationToken.Register(static s => ((TcpByteStream)s!).Dispose(), _tcp))
                {
                    await Task.Run(() => protocol.Connect(client), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                try { protocol.Close(); } catch { }
                throw;
            }

            _client = client;
            _protocol = protocol;
            _appData = protocol.Stream;
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Stream appData = _appData ?? throw new InvalidOperationException("The TLS stream is not connected.");
            cancellationToken.ThrowIfCancellationRequested();
            // protocol.Stream.Read returns the decrypted bytes already buffered (down to 1), so small reads — like the
            // OpenConnect header parser's byte-at-a-time reads — are served without over-reading the next CSTP frame.
            return await Task.Run(() =>
            {
                if (MemoryMarshal.TryGetArray<byte>(buffer, out ArraySegment<byte> segment))
                    return appData.Read(segment.Array!, segment.Offset, segment.Count);
                byte[] temp = new byte[buffer.Length];
                int read = appData.Read(temp, 0, temp.Length);
                if (read > 0) temp.AsMemory(0, read).CopyTo(buffer);
                return read;
            }, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Stream appData = _appData ?? throw new InvalidOperationException("The TLS stream is not connected.");
            cancellationToken.ThrowIfCancellationRequested();
            byte[] copy = buffer.ToArray(); // BC's stream writes a byte[]+offset+len; copy out of the Memory
            await Task.Run(() => appData.Write(copy, 0, copy.Length), cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public byte[] ExportKeyingMaterial(string label, ReadOnlySpan<byte> context, int length)
        {
            ExporterTlsClient client = _client ?? throw new InvalidOperationException("The TLS stream is not connected.");
            // The master secret is gone after the handshake, so the value must have been pre-registered via
            // RequestKeyingMaterialExport and captured at handshake-complete; return that cached result.
            if (client.TryGetCachedExport(label, context, length, out byte[] result)) return result;
            throw new InvalidOperationException(
                $"No keying-material export was registered for label '{label}'; call {nameof(RequestKeyingMaterialExport)} before {nameof(ConnectAsync)}.");
        }

        /// <summary>A queued/cached RFC 5705 export: the label, context and length, plus the captured output once computed.</summary>
        sealed class KeyingMaterialRequest
        {
            public KeyingMaterialRequest(string label, byte[] context, int length)
            {
                Label = label;
                Context = context;
                Length = length;
            }

            public string Label { get; }
            public byte[] Context { get; }
            public int Length { get; }
            public byte[]? Output { get; set; }

            public bool Matches(string label, ReadOnlySpan<byte> context, int length)
                => Length == length && Label == label && context.SequenceEqual(Context);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            Dispose();
            return default;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            try { _protocol?.Close(); } catch { } // sends close_notify (best-effort)
            _tcp.Dispose();
            RemoteCertificate?.Dispose();
        }

        /// <summary>
        /// The TLS 1.2 client: pins the protocol version (DTLS-free interop is simplest at TLS 1.2), accepts the server
        /// certificate (capturing it and applying the optional validation callback), supplies no client credentials, and
        /// captures its <see cref="TlsClientContext"/> so the RFC 5705 exporter can run after the handshake.
        /// </summary>
        sealed class ExporterTlsClient : DefaultTlsClient
        {
            readonly string _host;
            readonly RemoteCertificateValidationCallback? _validation;
            readonly Action<X509Certificate2?> _onCertificate;
            readonly List<KeyingMaterialRequest> _exports;

            public ExporterTlsClient(TlsCrypto crypto, string host,
                RemoteCertificateValidationCallback? validation, Action<X509Certificate2?> onCertificate,
                List<KeyingMaterialRequest> exports)
                : base(crypto)
            {
                _host = host;
                _validation = validation;
                _onCertificate = onCertificate;
                _exports = exports;
            }

            // TLS 1.2 only — matches the DTLS client's version pinning and keeps interop with ocserv simple.
            protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

            // Compute every registered RFC 5705 export here, while the master secret is still alive — BouncyCastle clears
            // it as soon as the handshake completes. We do NOT use TlsContext.ExportKeyingMaterial: it refuses a
            // non-extended-master-secret TLS 1.2 session, but ocserv (gnutls) negotiates the OpenConnect CSTP session
            // WITHOUT EMS yet still derives the PSK from it (gnutls's plain TLS 1.2 PRF over the master secret, not the
            // EMS-gated path). So compute the exporter directly — PRF(master_secret, label, client_random + server_random
            // [+ uint16 len + ctx]) — matching gnutls and sidestepping the EMS guard. This is the legacy RFC 5705
            // exporter behaviour AnyConnect interop requires.
            public override void NotifyHandshakeComplete()
            {
                base.NotifyHandshakeComplete();
                if (_exports.Count == 0) return;
                TlsClientContext ctx = m_context ?? throw new InvalidOperationException("TLS context not initialised.");
                SecurityParameters sp = ctx.SecurityParameters;
                TlsSecret? masterSecret = sp.MasterSecret;
                if (masterSecret is null || !masterSecret.IsAlive()) return; // leaves outputs null ⇒ export throws later

                byte[] clientRandom = sp.ClientRandom;
                byte[] serverRandom = sp.ServerRandom;
                int prf = sp.PrfAlgorithm;
                foreach (KeyingMaterialRequest req in _exports)
                {
                    bool hasContext = req.Context.Length > 0;
                    int seedLen = clientRandom.Length + serverRandom.Length + (hasContext ? 2 + req.Context.Length : 0);
                    byte[] seed = new byte[seedLen];
                    int p = 0;
                    Buffer.BlockCopy(clientRandom, 0, seed, p, clientRandom.Length); p += clientRandom.Length;
                    Buffer.BlockCopy(serverRandom, 0, seed, p, serverRandom.Length); p += serverRandom.Length;
                    if (hasContext)
                    {
                        seed[p++] = (byte)(req.Context.Length >> 8);
                        seed[p++] = (byte)req.Context.Length;
                        Buffer.BlockCopy(req.Context, 0, seed, p, req.Context.Length);
                    }
                    req.Output = masterSecret.DeriveUsingPrf(prf, req.Label, seed, req.Length).Extract();
                }
            }

            // Returns a cached export captured at handshake-complete (the master secret is gone by now).
            public bool TryGetCachedExport(string label, ReadOnlySpan<byte> context, int length, out byte[] output)
            {
                foreach (KeyingMaterialRequest req in _exports)
                    if (req.Output is not null && req.Matches(label, context, length))
                    {
                        output = req.Output;
                        return true;
                    }
                output = Array.Empty<byte>();
                return false;
            }

            public override TlsAuthentication GetAuthentication()
                => new CallbackAuthentication(_host, _validation, _onCertificate);

            sealed class CallbackAuthentication : TlsAuthentication
            {
                readonly string _host;
                readonly RemoteCertificateValidationCallback? _validation;
                readonly Action<X509Certificate2?> _onCertificate;

                public CallbackAuthentication(string host, RemoteCertificateValidationCallback? validation,
                    Action<X509Certificate2?> onCertificate)
                {
                    _host = host;
                    _validation = validation;
                    _onCertificate = onCertificate;
                }

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    X509Certificate2? leaf = null;
                    TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();
                    if (chain.Length > 0)
                        leaf = new X509Certificate2(chain[0].GetEncoded());
                    _onCertificate(leaf);

                    // No callback ⇒ accept any (identity is bound by the OpenConnect cookie, not PKI). A callback may
                    // reject; we have no SslPolicyErrors/chain here, so pass the leaf + None and let the callback decide.
                    if (_validation is null) return;
                    bool ok = _validation(_host, leaf, chain: null, System.Net.Security.SslPolicyErrors.None);
                    if (!ok) throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }

                public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null; // anonymous client
            }
        }
    }
}
