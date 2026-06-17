namespace TqkLibrary.VpnClient.OpenConnect.Enums
{
    /// <summary>
    /// The CSTP session-rekey method an OpenConnect/ocserv gateway requests in the <c>X-CSTP-Rekey-Method</c> header
    /// (alongside the <c>X-CSTP-Rekey-Time</c> period). After the period elapses the client refreshes the session so the
    /// gateway does not time the old one out. Re-implemented from the published OpenConnect/ocserv behaviour
    /// (draft-mavrogiannopoulos-openconnect), not copied from the GPL source.
    /// </summary>
    public enum OpenConnectRekeyMethod
    {
        /// <summary>No rekey requested (<c>none</c>, an unknown value, or the header absent) — the session lives off DPD/keep-alive.</summary>
        None = 0,

        /// <summary>
        /// <c>ssl</c>: the gateway expects a TLS renegotiation on the existing connection. <see cref="SslStream"/> on
        /// net8/netstandard2.0 exposes no client-initiated renegotiation (only net9+), so the driver treats this like
        /// <see cref="NewTunnel"/> — it re-establishes a fresh tunnel make-before-break (documented fallback).
        /// </summary>
        Ssl = 1,

        /// <summary><c>new-tunnel</c>: the client re-establishes a fresh tunnel (new auth + CONNECT) and swaps the data plane onto it.</summary>
        NewTunnel = 2,
    }
}
