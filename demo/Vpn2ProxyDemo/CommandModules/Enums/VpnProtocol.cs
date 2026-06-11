namespace Vpn2ProxyDemo.CommandModules.Enums
{
    /// <summary>Giao thức VPN demo hỗ trợ — map từ scheme của option <c>--vpn</c> (<c>sstp</c> / <c>l2tp</c>).</summary>
    internal enum VpnProtocol
    {
        /// <summary>MS-SSTP qua TLS/443.</summary>
        Sstp,

        /// <summary>L2TP/IPsec (IKEv1 PSK "vpn", NAT-T).</summary>
        L2tp,
    }
}
