namespace TqkLibrary.VpnClient.Ppp.Enums
{
    /// <summary>IPV6CP configuration option types (RFC 5072 §4).</summary>
    public enum Ipv6cpOptionType : byte
    {
        /// <summary>Interface-Identifier — the 8-byte IID that forms the fe80::/64 link-local address (RFC 5072 §4.1).</summary>
        InterfaceIdentifier = 1,

        /// <summary>IPv6-Compression-Protocol (RFC 5072 §4.2) — not negotiated by this client; rejected if the peer asks.</summary>
        CompressionProtocol = 2,
    }
}
