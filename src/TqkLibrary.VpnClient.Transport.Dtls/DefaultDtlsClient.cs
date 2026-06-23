using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// The DTLS 1.2 <see cref="TlsClient"/> driven by <see cref="DtlsClientProtocol"/>. It pins the protocol version to
    /// DTLS 1.2 (DTLS 1.3 is not yet widely deployed by VPN gateways and not all of BouncyCastle's DTLS 1.3 paths are
    /// exercised here). Server-certificate validation is delegated to the optional
    /// <see cref="DtlsServerCertificateValidationCallback"/>; with none supplied any certificate is accepted (the
    /// OpenConnect cookie still authorises the tunnel). This client is certificate-anonymous (no client certificate) —
    /// DTLS in the OpenConnect data path is authorised by the CSTP session, not mutual PKI.
    /// <para>
    /// <b>Legacy AnyConnect DTLS session resumption (V5.c live):</b> ocserv's <c>dtls-legacy</c> path does NOT run a full
    /// DTLS handshake. Instead the client transports a 48-byte master secret in-band over the authenticated TLS CONNECT
    /// (<c>X-DTLS-Master-Secret</c>); the gateway answers with a 32-byte session id (<c>X-DTLS-Session-ID</c>) and the
    /// chosen cipher (<c>X-DTLS-CipherSuite</c>). The client then offers an <b>abbreviated</b> DTLS handshake whose
    /// <c>ClientHello.session_id</c> equals that session id and whose pre-shared master secret resumes the session — no
    /// certificate is exchanged. When <see cref="DtlsResumptionParameters"/> is supplied this client builds exactly that
    /// resumable <see cref="TlsSession"/> (<see cref="TlsUtilities.ImportSession"/>) and offers only the resumed cipher
    /// suite; ocserv recognises the session id and completes the abbreviated handshake. Without it, the client offers a
    /// full handshake (the offline loopback / non-legacy gateways) — that is why the offline self-pair never exposed the
    /// missing session id, and only the live ocserv ("invalid session ID size (0)") did.
    /// </para>
    /// </summary>
    sealed class DefaultDtlsClient : DefaultTlsClient
    {
        readonly DtlsServerCertificateValidationCallback? _certificateValidationCallback;
        readonly DtlsResumptionParameters? _resumption;
        readonly TlsSession? _sessionToResume;

        public DefaultDtlsClient(TlsCrypto crypto, DtlsServerCertificateValidationCallback? certificateValidationCallback,
            DtlsResumptionParameters? resumption = null)
            : base(crypto)
        {
            _certificateValidationCallback = certificateValidationCallback;
            _resumption = resumption;
            // Build the resumable session once (the master secret/session id/cipher came in-band over the TLS CONNECT).
            // ocserv's legacy DTLS resumption runs over DTLS 1.0 (the "hello v1.0" on the wire), so the resumed session is
            // pinned to DTLS 1.0 — a DTLS 1.2 resumption ClientHello is rejected by the legacy server ("dtls_mainloop
            // failed"). The full-handshake path (no resumption) still uses DTLS 1.2.
            if (resumption is not null)
            {
                TlsSecret masterSecret = crypto.CreateSecret(resumption.MasterSecret);
                SessionParameters parameters = new SessionParameters.Builder()
                    .SetCipherSuite(resumption.CipherSuite)
                    .SetMasterSecret(masterSecret)
                    .SetNegotiatedVersion(ProtocolVersion.DTLSv10)
                    .SetExtendedMasterSecret(false) // legacy AnyConnect DTLS predates RFC 7627
                    .Build();
                _sessionToResume = TlsUtilities.ImportSession(resumption.SessionId, parameters);
            }
        }

        /// <summary>
        /// Offer DTLS 1.2 down to DTLS 1.0 when resuming a legacy session (ocserv legacy DTLS resumes over DTLS 1.0); a
        /// full handshake offers DTLS 1.2 only (RFC 6347).
        /// </summary>
        protected override ProtocolVersion[] GetSupportedVersions() => _resumption is not null
            ? ProtocolVersion.DTLSv12.DownTo(ProtocolVersion.DTLSv10)
            : ProtocolVersion.DTLSv12.Only();

        /// <summary>
        /// When resuming a legacy AnyConnect session, offer only the resumed cipher suite (the session is bound to it).
        /// Otherwise offer AEAD suites (forward-secret ECDHE/DHE first, then RSA key-transport) for a full handshake.
        /// </summary>
        protected override int[] GetSupportedCipherSuites() => _resumption is not null
            ? new[] { _resumption.CipherSuite }
            : new[]
            {
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            };

        /// <summary>The resumable session to offer in the ClientHello (carries the session id ocserv expects); null = full handshake.</summary>
        public override TlsSession? GetSessionToResume() => _sessionToResume;

        /// <summary>
        /// Allow resumption of a legacy (no extended-master-secret) session. ocserv's <c>dtls-legacy</c> session predates
        /// RFC 7627, so the session is built with <c>SetExtendedMasterSecret(false)</c>; without this override BouncyCastle
        /// zeroes the offered <c>legacy_session_id</c> for a non-EMS session and the abbreviated handshake never starts
        /// (the gateway then sees the empty session id). Only relevant while resuming.
        /// </summary>
        public override bool AllowLegacyResumption() => _resumption is not null || base.AllowLegacyResumption();

        /// <inheritdoc/>
        public override TlsAuthentication GetAuthentication() => new CallbackAuthentication(_certificateValidationCallback);

        /// <summary>
        /// Bridges the server-certificate step to <see cref="DtlsServerCertificateValidationCallback"/> and supplies no
        /// client credentials (anonymous client). Rejecting the certificate throws a fatal handshake alert. On a resumed
        /// handshake the gateway sends no certificate, so this is only reached on a full handshake.
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
