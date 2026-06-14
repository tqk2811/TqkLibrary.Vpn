namespace TqkLibrary.Vpn.Abstractions.Net
{
    /// <summary>
    /// Which IP address family to prefer when resolving a VPN server host (the <b>outer</b> transport). The other
    /// family is still used as a fallback when the preferred one has no address (RFC 6724 leaves the choice to the
    /// application). <see cref="Auto"/> keeps the historical IPv4-first behaviour so existing live setups are unaffected.
    /// </summary>
    public enum AddressFamilyPreference
    {
        /// <summary>Prefer IPv4, fall back to IPv6 (default — preserves legacy behaviour).</summary>
        Auto = 0,

        /// <summary>Prefer IPv4, fall back to IPv6.</summary>
        IPv4 = 1,

        /// <summary>Prefer IPv6, fall back to IPv4.</summary>
        IPv6 = 2,
    }
}
