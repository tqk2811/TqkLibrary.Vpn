namespace TqkLibrary.VpnClient.OpenVpn.Enums
{
    /// <summary>The transport an OpenVPN session runs over (the client side of the <c>proto</c> directive).</summary>
    public enum OpenVpnProtocol
    {
        /// <summary>UDP — one datagram per packet (the default, and the only one for V2.a–V2.f until V2.g adds TCP).</summary>
        Udp = 0,

        /// <summary>TCP (<c>tcp</c>/<c>tcp-client</c>) — each packet prefixed with a 16-bit length.</summary>
        Tcp = 1,
    }
}
