using Org.BouncyCastle.Tls;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// The parameters for the OpenConnect <b>DTLS 1.2 PSK</b> full handshake (cipher <c>PSK-NEGOTIATE</c>, ocserv ≥ 0.11.5
    /// / modern AnyConnect). Unlike legacy <see cref="DtlsResumptionParameters"/> this is a <i>real</i> DTLS handshake
    /// with a TLS-PSK key exchange — no in-band master secret. The pre-shared key is derived <b>out of band</b> from the
    /// CSTP control-channel TLS session via an RFC 5705 exporter (label <c>"EXPORTER-openconnect-psk"</c>, empty context,
    /// 32 bytes), so it is never transported on the wire. The <see cref="SessionId"/> (the hex-decoded
    /// <c>X-DTLS-App-ID</c>) is copied into the DTLS <c>ClientHello.session_id</c> so the gateway can correlate the UDP
    /// session with the CSTP one (draft-mavrogiannopoulos-openconnect §DTLS).
    /// </summary>
    public sealed class DtlsPskParameters
    {
        /// <summary>The default PSK GCM cipher suites the client offers, strongest first (the OpenConnect PSK path uses these).</summary>
        public static readonly int[] DefaultCipherSuites =
        {
            CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384, // 0x00A9
            CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, // 0x00A8
        };

        /// <summary>
        /// Creates the PSK parameters. <paramref name="pskIdentity"/> is the PSK identity sent on the wire (OpenConnect
        /// uses the ASCII string <c>"psk"</c>); <paramref name="pskKey"/> is the 32-byte RFC 5705 exporter output;
        /// <paramref name="sessionId"/> is the hex-decoded <c>X-DTLS-App-ID</c> placed in <c>ClientHello.session_id</c>;
        /// <paramref name="cipherSuites"/> are the offered PSK suites (defaults to <see cref="DefaultCipherSuites"/>).
        /// </summary>
        public DtlsPskParameters(byte[] pskIdentity, byte[] pskKey, byte[] sessionId, int[]? cipherSuites = null)
        {
            PskIdentity = pskIdentity ?? throw new ArgumentNullException(nameof(pskIdentity));
            PskKey = pskKey ?? throw new ArgumentNullException(nameof(pskKey));
            SessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
            CipherSuites = cipherSuites is { Length: > 0 } ? cipherSuites : DefaultCipherSuites;
        }

        /// <summary>The PSK identity sent on the wire (OpenConnect: ASCII <c>"psk"</c>).</summary>
        public byte[] PskIdentity { get; }

        /// <summary>The 32-byte pre-shared key (RFC 5705 exporter over the CSTP TLS session, label <c>"EXPORTER-openconnect-psk"</c>).</summary>
        public byte[] PskKey { get; }

        /// <summary>The DTLS <c>ClientHello.session_id</c> bytes (hex-decoded <c>X-DTLS-App-ID</c>, 16–32 bytes).</summary>
        public byte[] SessionId { get; }

        /// <summary>The PSK GCM cipher suites the client offers (BouncyCastle <see cref="CipherSuite"/> ids), strongest first.</summary>
        public int[] CipherSuites { get; }
    }
}
