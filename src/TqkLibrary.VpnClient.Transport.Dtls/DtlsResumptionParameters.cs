namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// The pre-shared parameters for a legacy AnyConnect DTLS <b>session resumption</b> (ocserv <c>dtls-legacy</c>), all
    /// transported in-band over the authenticated TLS CONNECT rather than negotiated on the wire. The DTLS client offers
    /// an abbreviated handshake whose <c>ClientHello.session_id</c> equals <see cref="SessionId"/> and whose pre-shared
    /// master secret is <see cref="MasterSecret"/>, on the resumed <see cref="CipherSuite"/> — so the gateway recognises
    /// the session and skips the certificate exchange. Supply null to <see cref="DtlsDatagramTransport"/> for a normal
    /// full DTLS handshake instead (the offline loopback / non-legacy gateways).
    /// </summary>
    public sealed class DtlsResumptionParameters
    {
        /// <summary>
        /// Creates the resumption parameters. <paramref name="masterSecret"/> is the 48-byte secret the client generated
        /// and sent as <c>X-DTLS-Master-Secret</c>; <paramref name="sessionId"/> is the gateway's <c>X-DTLS-Session-ID</c>
        /// (the ClientHello session id); <paramref name="cipherSuite"/> is the BouncyCastle cipher-suite id the gateway
        /// chose (<c>X-DTLS-CipherSuite</c>, mapped by <see cref="DtlsCipherSuiteMap"/>).
        /// </summary>
        public DtlsResumptionParameters(byte[] masterSecret, byte[] sessionId, int cipherSuite)
        {
            MasterSecret = masterSecret ?? throw new ArgumentNullException(nameof(masterSecret));
            SessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
            CipherSuite = cipherSuite;
        }

        /// <summary>The 48-byte pre-shared master secret (the client's <c>X-DTLS-Master-Secret</c>).</summary>
        public byte[] MasterSecret { get; }

        /// <summary>The DTLS ClientHello session id the gateway expects (its <c>X-DTLS-Session-ID</c>, decoded from hex).</summary>
        public byte[] SessionId { get; }

        /// <summary>The BouncyCastle cipher-suite id of the resumed session (from <c>X-DTLS-CipherSuite</c>).</summary>
        public int CipherSuite { get; }
    }
}
