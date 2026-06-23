using System.Net;
using System.Net.Security;
using TqkLibrary.VpnClient.Transport.Tls;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// The production <see cref="IOpenConnectTransportFactory"/>: opens a real TCP socket and completes the TLS
    /// handshake via the shared <see cref="TlsByteStream"/> (roadmap F.1's <c>Transport.Tls</c>), yielding the byte
    /// stream the HTTP auth/CONNECT and the CSTP tunnel ride. An optional
    /// <see cref="RemoteCertificateValidationCallback"/> validates the gateway certificate (null = accept any — the
    /// AnyConnect cookie still authorises the tunnel, but production callers should pin/validate the cert). The socket
    /// I/O is exercised live (lab Q.1, roadmap V5.b); the offline tests drive the connection through an in-process
    /// loopback factory instead.
    /// </summary>
    public sealed class OpenConnectSocketTransportFactory : IOpenConnectTransportFactory
    {
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;

        /// <summary>Creates the factory. <paramref name="certificateValidationCallback"/> validates the gateway cert (null = accept any).</summary>
        public OpenConnectSocketTransportFactory(RemoteCertificateValidationCallback? certificateValidationCallback = null)
            => _certificateValidationCallback = certificateValidationCallback;

        /// <inheritdoc/>
        public async Task<OpenConnectTransportHandle> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            // The caller has already resolved the gateway (to correlate the parallel DTLS path), so use the
            // pre-resolved endpoint while keeping the original host as the TLS TargetHost (SNI).
            var stream = new TlsByteStream(host, remote, _certificateValidationCallback);
            await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return new OpenConnectTransportHandle(stream);
        }
    }
}
