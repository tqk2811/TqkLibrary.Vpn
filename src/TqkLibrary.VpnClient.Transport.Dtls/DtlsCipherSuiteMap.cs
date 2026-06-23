using Org.BouncyCastle.Tls;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// Maps the OpenSSL-style DTLS cipher-suite names ocserv returns in <c>X-DTLS-CipherSuite</c> for the <b>legacy</b>
    /// AnyConnect DTLS path (e.g. <c>AES256-SHA</c>) onto BouncyCastle <see cref="CipherSuite"/> ids. Legacy AnyConnect
    /// DTLS resumption (ocserv <c>dtls-legacy</c>) negotiates the cipher in-band over the TLS CONNECT, so the on-wire DTLS
    /// ClientHello must offer exactly the suite the gateway chose — and only the <b>RSA-key-transport CBC</b> suites
    /// ocserv uses for that path (the resumed session has no fresh key exchange, and ocserv's legacy DTLS server speaks
    /// CBC). A resolvable name is therefore the signal that the gateway wants a legacy-resumption (abbreviated) DTLS
    /// handshake; a modern gateway advertising an AEAD/GCM suite (or none) is left unresolved so the client runs a normal
    /// full handshake instead. Pure lookup, no state.
    /// </summary>
    public static class DtlsCipherSuiteMap
    {
        /// <summary>
        /// Resolves a legacy OpenSSL DTLS cipher-suite name (<c>X-DTLS-CipherSuite</c>) to a BouncyCastle
        /// <see cref="CipherSuite"/> id. Returns true and sets <paramref name="cipherSuite"/> for a known legacy CBC
        /// suite (the signal to resume); false for an unknown/empty name or an AEAD suite (⇒ full handshake).
        /// </summary>
        public static bool TryResolve(string? name, out int cipherSuite)
        {
            cipherSuite = 0;
            if (string.IsNullOrWhiteSpace(name)) return false;
            switch (name.Trim().ToUpperInvariant())
            {
                case "AES256-SHA": cipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA; return true;       // 0x0035
                case "AES128-SHA": cipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA; return true;       // 0x002F
                case "AES256-SHA256": cipherSuite = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256; return true; // 0x003D
                case "AES128-SHA256": cipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256; return true; // 0x003C
                default: return false; // AEAD/GCM or unknown ⇒ not a legacy resumption (the client does a full handshake)
            }
        }
    }
}
