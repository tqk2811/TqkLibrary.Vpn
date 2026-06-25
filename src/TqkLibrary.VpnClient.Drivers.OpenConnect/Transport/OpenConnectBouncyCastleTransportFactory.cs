using System.Net;
using System.Net.Security;
using System.Text;
using TqkLibrary.VpnClient.Transport.Tls;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect.Transport
{
    /// <summary>
    /// An <see cref="IOpenConnectTransportFactory"/> that completes the CSTP control-channel TLS handshake through
    /// <b>BouncyCastle</b> (<see cref="BouncyCastleTlsByteStream"/>) instead of the BCL <see cref="SslStream"/>. The only
    /// reason to choose it over <see cref="OpenConnectSocketTransportFactory"/> is that the returned stream also
    /// implements <c>ITlsKeyingMaterialExporter</c>, so the connection can derive the modern <b>DTLS 1.2 PSK</b>
    /// (<c>PSK-NEGOTIATE</c>) pre-shared key from the CSTP TLS session (RFC 5705 exporter) — the legacy AnyConnect DTLS
    /// path and the SslStream factory cannot do that. An optional
    /// <see cref="RemoteCertificateValidationCallback"/> validates the gateway certificate (null = accept any — the
    /// AnyConnect cookie still authorises the tunnel).
    /// </summary>
    public sealed class OpenConnectBouncyCastleTransportFactory : IOpenConnectTransportFactory
    {
        /// <summary>The RFC 5705 exporter label + key length for the OpenConnect DTLS 1.2 PSK (draft-mavrogiannopoulos-openconnect).</summary>
        internal const string DtlsPskExporterLabel = "EXPORTER-openconnect-psk";
        internal const int DtlsPskKeyLength = 32;

        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;

        /// <summary>Creates the factory. <paramref name="certificateValidationCallback"/> validates the gateway cert (null = accept any).</summary>
        public OpenConnectBouncyCastleTransportFactory(RemoteCertificateValidationCallback? certificateValidationCallback = null)
            => _certificateValidationCallback = certificateValidationCallback;

        /// <inheritdoc/>
        public async Task<OpenConnectTransportHandle> ConnectAsync(string host, IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            // Keep the original host as the TLS TargetHost (SNI) while connecting the pre-resolved endpoint (the caller
            // resolved it to correlate the parallel DTLS path).
            var stream = new BouncyCastleTlsByteStream(host, remote, _certificateValidationCallback);
            // Register the DTLS-PSK export BEFORE the handshake: BouncyCastle clears the TLS master secret once the
            // handshake completes, so the PSK must be captured during it. The driver reads it back after CONNECT.
            stream.RequestKeyingMaterialExport(DtlsPskExporterLabel, ReadOnlySpan<byte>.Empty, DtlsPskKeyLength);
            await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return new OpenConnectTransportHandle(stream);
        }
    }
}
