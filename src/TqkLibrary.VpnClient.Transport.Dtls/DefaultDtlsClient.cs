using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// The DTLS 1.2 <see cref="TlsClient"/> driven by <see cref="DtlsClientProtocol"/>: it pins the protocol version to
    /// DTLS 1.2 (DTLS 1.3 is not yet widely deployed by VPN gateways and not all of BouncyCastle's DTLS 1.3 paths are
    /// exercised here) and offers a small set of AEAD cipher suites (AES-GCM, plus ChaCha20-Poly1305). Server-certificate
    /// validation is delegated to the optional <see cref="DtlsServerCertificateValidationCallback"/>; with none supplied,
    /// any certificate is accepted (the OpenConnect cookie still authorises the tunnel). This client is
    /// certificate-anonymous (no client certificate) — DTLS in the OpenConnect data path is authorised by the CSTP
    /// session, not mutual PKI.
    /// </summary>
    sealed class DefaultDtlsClient : DefaultTlsClient
    {
        readonly DtlsServerCertificateValidationCallback? _certificateValidationCallback;

        public DefaultDtlsClient(TlsCrypto crypto, DtlsServerCertificateValidationCallback? certificateValidationCallback)
            : base(crypto)
            => _certificateValidationCallback = certificateValidationCallback;

        /// <summary>Offer only DTLS 1.2 (RFC 6347).</summary>
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        /// <summary>Offer AEAD suites only (forward-secret ECDHE/DHE first, then RSA key-transport as a fallback).</summary>
        protected override int[] GetSupportedCipherSuites() => new[]
        {
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        };

        /// <inheritdoc/>
        public override TlsAuthentication GetAuthentication() => new CallbackAuthentication(_certificateValidationCallback);

        /// <summary>
        /// Bridges the server-certificate step to <see cref="DtlsServerCertificateValidationCallback"/> and supplies no
        /// client credentials (anonymous client). Rejecting the certificate throws a fatal handshake alert.
        /// </summary>
        sealed class CallbackAuthentication : TlsAuthentication
        {
            readonly DtlsServerCertificateValidationCallback? _callback;
            public CallbackAuthentication(DtlsServerCertificateValidationCallback? callback) => _callback = callback;

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                if (_callback is null) return; // no callback ⇒ accept any certificate
                if (!_callback(serverCertificate))
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null; // anonymous client
        }
    }
}
