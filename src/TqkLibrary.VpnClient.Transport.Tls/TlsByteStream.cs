using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Transport.Tls
{
    /// <summary>
    /// The shared TLS-over-TCP byte stream behind <see cref="ITlsByteStream"/>: a <see cref="TcpByteStream"/> (roadmap
    /// F.1's <c>Transport.Tcp</c>) wrapped in an <see cref="SslStream"/>. It is the single concrete TLS transport the
    /// SSTP, SoftEther and OpenConnect drivers share. The server certificate is captured into
    /// <see cref="RemoteCertificate"/> during the handshake (SSTP's crypto binding [MS-SSTP] §3.2.4 hashes it); the TLS
    /// validation accepts any certificate by default — these protocols bind the server identity through their own
    /// auth/crypto binding rather than PKI — unless a <see cref="RemoteCertificateValidationCallback"/> is supplied to
    /// validate it (roadmap P0.6).
    /// <para>
    /// <see cref="ConnectAsync"/> honours its <see cref="CancellationToken"/> on both target frameworks: the inner
    /// <see cref="TcpByteStream"/> cancels the TCP connect, and the TLS handshake uses native overloads on net8.0 and
    /// cancel-by-dispose on netstandard2.0.
    /// </para>
    /// </summary>
    public sealed class TlsByteStream : ITlsByteStream, IDisposable
    {
        readonly TcpByteStream _tcp;
        readonly string _host;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        SslStream? _ssl;

        /// <summary>
        /// Creates a TLS byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).
        /// <paramref name="certificateValidationCallback"/> validates the server certificate during the TLS handshake;
        /// when <c>null</c> (the default) any certificate is accepted (the protocol binds the server identity through its
        /// own auth/crypto binding, not PKI). The server certificate is captured into <see cref="RemoteCertificate"/>
        /// either way. <paramref name="addressFamilyPreference"/> selects IPv4/IPv6 for the outer TCP connection when the
        /// host resolves to both; <paramref name="hostResolver"/> performs the name→address lookup (default: DNS).
        /// </summary>
        public TlsByteStream(string host, int port = 443, RemoteCertificateValidationCallback? certificateValidationCallback = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(host, port, addressFamilyPreference, hostResolver);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <summary>
        /// Creates a TLS byte stream over an already-resolved <paramref name="remote"/> endpoint, keeping
        /// <paramref name="host"/> as the TLS TargetHost (SNI). Used when the caller resolves the address itself (e.g. to
        /// correlate a parallel DTLS path). See the primary constructor for the certificate-validation semantics.
        /// </summary>
        public TlsByteStream(string host, IPEndPoint remote, RemoteCertificateValidationCallback? certificateValidationCallback = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _tcp = new TcpByteStream(remote);
            _certificateValidationCallback = certificateValidationCallback;
        }

        /// <inheritdoc/>
        public X509Certificate2? RemoteCertificate { get; private set; }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            // Connect the TCP layer first (it resolves + opens the socket in the chosen address family); the host string
            // is still used as the TLS TargetHost (SNI) below — only the connect uses the concrete address.
            await _tcp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            // Capture the cert (SSTP's crypto binding hashes it), then defer the accept/reject decision to the configured
            // callback; no callback ⇒ accept any certificate (identity is bound by the protocol's own auth, not PKI).
            var ssl = new SslStream(_tcp.Stream, leaveInnerStreamOpen: false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate != null) RemoteCertificate = new X509Certificate2(certificate);
                return _certificateValidationCallback?.Invoke(sender, certificate, chain, sslPolicyErrors) ?? true;
            });
            _ssl = ssl;
#if NET5_0_OR_GREATER
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = _host }, cancellationToken).ConfigureAwait(false);
#else
            using (cancellationToken.Register(() => { try { ssl.Dispose(); } catch { } }))
            {
                try { await ssl.AuthenticateAsClientAsync(_host).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            SslStream ssl = _ssl ?? throw new InvalidOperationException("The TLS stream is not connected.");
#if NET5_0_OR_GREATER
            return await ssl.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray<byte>(buffer, out ArraySegment<byte> segment))
                return await ssl.ReadAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            byte[] temp = new byte[buffer.Length];
            int read = await ssl.ReadAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
            temp.AsMemory(0, read).CopyTo(buffer);
            return read;
#endif
        }

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            SslStream ssl = _ssl ?? throw new InvalidOperationException("The TLS stream is not connected.");
#if NET5_0_OR_GREATER
            await ssl.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
                await ssl.WriteAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            else
            {
                byte[] temp = buffer.ToArray();
                await ssl.WriteAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
            }
#endif
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
            _ssl?.Dispose();          // closes the inner NetworkStream (leaveInnerStreamOpen: false)
            _tcp.Dispose();           // closes the TcpClient (idempotent on the already-closed stream)
            RemoteCertificate?.Dispose();
        }
    }
}
