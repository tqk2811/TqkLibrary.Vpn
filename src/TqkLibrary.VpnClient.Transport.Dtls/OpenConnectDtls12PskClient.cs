using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// The DTLS 1.2 <b>PSK</b> client for the OpenConnect data path (cipher <c>PSK-NEGOTIATE</c>, ocserv ≥ 0.11.5 /
    /// modern AnyConnect). It runs a full DTLS 1.2 handshake with a TLS-PSK key exchange — no certificate, no legacy
    /// resumption — so it sidesteps the GnuTLS↔BouncyCastle interop failure the abbreviated legacy-resumption path hit.
    /// The pre-shared key (<see cref="DtlsPskParameters.PskKey"/>) is derived out of band from the CSTP TLS session
    /// (RFC 5705 exporter); the PSK identity (<see cref="DtlsPskParameters.PskIdentity"/>, <c>"psk"</c>) is sent on the
    /// wire after the ServerHello.
    /// <para>
    /// <b>Forcing the ClientHello.session_id = X-DTLS-App-ID:</b> the protocol requires the client to copy the gateway's
    /// hex-decoded <c>X-DTLS-App-ID</c> into the DTLS <c>ClientHello.session_id</c> so the gateway can correlate the UDP
    /// session with the CSTP one. BouncyCastle only emits a <c>session_id</c> via <see cref="GetSessionToResume"/>, so we
    /// import a throwaway <see cref="TlsSession"/> keyed by the App-ID (with a dummy master secret and one of the offered
    /// PSK suites / DTLS 1.2 / no extended-master-secret, satisfying <c>DtlsClientProtocol</c>'s session-id retention
    /// rules). The gateway answers with a <i>fresh</i> ServerHello (no real resume), so BouncyCastle takes the
    /// full-handshake branch and the real PSK key exchange runs — the imported session only seeds the session_id.
    /// </para>
    /// </summary>
    sealed class OpenConnectDtls12PskClient : PskTlsClient
    {
        readonly DtlsPskParameters _psk;
        readonly DtlsServerCertificateValidationCallback? _certificateValidationCallback;
        readonly TlsSession _sessionForId;

        public OpenConnectDtls12PskClient(TlsCrypto crypto, DtlsPskParameters psk,
            DtlsServerCertificateValidationCallback? certificateValidationCallback)
            : base(crypto, new BasicTlsPskIdentity(psk.PskIdentity, psk.PskKey))
        {
            _psk = psk;
            _certificateValidationCallback = certificateValidationCallback;

            // Seed ClientHello.session_id with the App-ID by importing a throwaway resumable session. The dummy master
            // secret is never used (the gateway returns a full handshake); it only has to be non-null and the suite /
            // version / EMS flags must pass DtlsClientProtocol's retention checks so the session_id survives into the wire.
            TlsSecret dummyMaster = crypto.CreateSecret(new byte[48]);
            SessionParameters parameters = new SessionParameters.Builder()
                .SetCipherSuite(psk.CipherSuites[0])
                .SetMasterSecret(dummyMaster)
                .SetNegotiatedVersion(ProtocolVersion.DTLSv12)
                .SetExtendedMasterSecret(false)
                .SetPskIdentity(psk.PskIdentity)
                .Build();
            _sessionForId = TlsUtilities.ImportSession(psk.SessionId, parameters);
        }

        /// <summary>DTLS 1.2 only (RFC 6347 over the PSK key exchange).</summary>
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        /// <summary>Offer only the PSK GCM suites the OpenConnect PSK path uses (strongest first).</summary>
        protected override int[] GetSupportedCipherSuites() => _psk.CipherSuites;

        /// <summary>The throwaway session whose id seeds <c>ClientHello.session_id</c> (= the App-ID); never actually resumed.</summary>
        public override TlsSession GetSessionToResume() => _sessionForId;

        /// <summary>Permit the non-extended-master-secret session id to survive into the ClientHello (the App-ID predates RFC 7627 semantics here).</summary>
        public override bool AllowLegacyResumption() => true;

        /// <inheritdoc/>
        public override TlsAuthentication GetAuthentication()
            => new CallbackAuthentication(_certificateValidationCallback);

        /// <summary>
        /// PSK handshakes carry no server certificate, so this is normally unused; it mirrors the certificate-anonymous
        /// authentication of the full/legacy DTLS client for safety (and applies the optional callback if a cert appears).
        /// </summary>
        sealed class CallbackAuthentication : TlsAuthentication
        {
            readonly DtlsServerCertificateValidationCallback? _callback;
            public CallbackAuthentication(DtlsServerCertificateValidationCallback? callback) => _callback = callback;

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                if (_callback is null) return;
                if (!_callback(serverCertificate))
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null; // anonymous client
        }
    }
}
