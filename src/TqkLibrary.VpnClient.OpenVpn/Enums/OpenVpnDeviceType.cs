namespace TqkLibrary.VpnClient.OpenVpn.Enums
{
    /// <summary>The virtual device type an OpenVPN session uses (the <c>dev</c> directive).</summary>
    public enum OpenVpnDeviceType
    {
        /// <summary>tun — L3, payload is a bare IP packet → <c>IPacketChannel</c> (the default; implemented first).</summary>
        Tun = 0,

        /// <summary>tap — L2, payload is an Ethernet frame → the L2 fabric (V2.g, after tun mode).</summary>
        Tap = 1,
    }
}
