using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Transport
{
    /// <summary>
    /// The real TLS-over-TCP byte stream a SoftEther session rides: a <see cref="TcpClient"/> wrapped in an
    /// <see cref="SslStream"/>. SoftEther binds the server identity through its own auth + watermark rather than PKI, so
    /// the TLS validation accepts any certificate by default; an optional callback can validate it instead. This is the
    /// same shape as the SSTP <c>TlsByteStream</c> (the shared <c>Transport.Tls</c> project is roadmap F.1);
    /// <see cref="ConnectAsync"/> honours its <see cref="CancellationToken"/> on both target frameworks.
    /// </summary>
    public sealed class SoftEtherTlsTransport : IByteStreamTransport
    {
        readonly string _host;
        readonly int _port;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        TcpClient? _tcp;
        SslStream? _ssl;
        X509Certificate2? _remoteCertificate;

        /// <summary>Creates a TLS byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).</summary>
        public SoftEtherTlsTransport(string host, int port,
            RemoteCertificateValidationCallback? certificateValidationCallback = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _certificateValidationCallback = certificateValidationCallback;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            IPAddress address = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            var tcp = new TcpClient(address.AddressFamily);
            _tcp = tcp;
#if NET5_0_OR_GREATER
            await tcp.ConnectAsync(address, _port, cancellationToken).ConfigureAwait(false);
#else
            using (cancellationToken.Register(() => { try { tcp.Dispose(); } catch { } }))
            {
                try { await tcp.ConnectAsync(address, _port).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif

            var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (certificate != null) _remoteCertificate = new X509Certificate2(certificate);
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
            _ssl?.Dispose();
            _tcp?.Dispose();
            _remoteCertificate?.Dispose();
            return default;
        }
    }
}
