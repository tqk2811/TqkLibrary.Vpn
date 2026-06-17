using System.Net.Security;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Transport
{
    /// <summary>
    /// The production <see cref="ISoftEtherTransportFactory"/>: opens a real TLS-over-TCP <see cref="SoftEtherTlsTransport"/>
    /// for each connect attempt. The optional <paramref name="certificateValidationCallback"/> validates the server
    /// certificate (null = accept any, since SoftEther binds identity through its own auth, not PKI).
    /// </summary>
    public sealed class SoftEtherTlsTransportFactory : ISoftEtherTransportFactory
    {
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly IHostResolver? _hostResolver;

        /// <summary>Creates the factory with an optional TLS certificate-validation callback and host resolver (default: DNS).</summary>
        public SoftEtherTlsTransportFactory(
            RemoteCertificateValidationCallback? certificateValidationCallback = null,
            IHostResolver? hostResolver = null)
        {
            _certificateValidationCallback = certificateValidationCallback;
            _hostResolver = hostResolver;
        }

        /// <inheritdoc/>
        public ValueTask<IByteStreamTransport> ConnectAsync(string host, int port,
            AddressFamilyPreference addressFamilyPreference, CancellationToken cancellationToken)
        {
            IByteStreamTransport transport = new SoftEtherTlsTransport(
                host, port, _certificateValidationCallback, addressFamilyPreference, _hostResolver);
            return new ValueTask<IByteStreamTransport>(transport);
        }
    }
}
