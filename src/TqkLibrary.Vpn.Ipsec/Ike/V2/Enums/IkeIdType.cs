namespace TqkLibrary.Vpn.Ipsec.Ike.V2.Enums
{
    /// <summary>Identification types for IDi/IDr payloads (RFC 7296 §3.5).</summary>
    public enum IkeIdType : byte
    {
        /// <summary>A single four-octet IPv4 address.</summary>
        Ipv4Address = 1,

        /// <summary>A fully-qualified domain name string.</summary>
        Fqdn = 2,

        /// <summary>An RFC 822 email address string.</summary>
        Rfc822Address = 3,

        /// <summary>A single sixteen-octet IPv6 address.</summary>
        Ipv6Address = 5,

        /// <summary>An opaque key id (vendor-specific).</summary>
        KeyId = 11,
    }
}
