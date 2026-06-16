namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums
{
    /// <summary>
    /// Configuration Attribute types carried inside a <see cref="IkeConfigType"/> payload (RFC 7296 §3.15.1, IANA
    /// "IKEv2 Configuration Payload Attribute Types"). The 15-bit type; the high reserved bit is always 0.
    /// </summary>
    public enum IkeConfigAttributeType : ushort
    {
        /// <summary>An IPv4 address assigned to the client (4 bytes).</summary>
        InternalIp4Address = 1,

        /// <summary>The IPv4 netmask of the internal network (4 bytes).</summary>
        InternalIp4Netmask = 2,

        /// <summary>An IPv4 DNS server address (4 bytes; may repeat).</summary>
        InternalIp4Dns = 3,

        /// <summary>An IPv4 NetBIOS name server (WINS) address (4 bytes).</summary>
        InternalIp4Nbns = 4,

        /// <summary>An IPv4 DHCP server the client may use (4 bytes).</summary>
        InternalIp4Dhcp = 6,

        /// <summary>The version string of the responder's application (variable).</summary>
        ApplicationVersion = 7,

        /// <summary>An IPv6 address + prefix length assigned to the client (16 + 1 bytes).</summary>
        InternalIp6Address = 8,

        /// <summary>An IPv6 DNS server address (16 bytes; may repeat).</summary>
        InternalIp6Dns = 10,

        /// <summary>An IPv6 DHCP server the client may use (16 bytes).</summary>
        InternalIp6Dhcp = 12,

        /// <summary>An IPv4 subnet (address + netmask) reachable through the SA (8 bytes).</summary>
        InternalIp4Subnet = 13,

        /// <summary>An IPv6 subnet (address + prefix length) reachable through the SA (17 bytes).</summary>
        InternalIp6Subnet = 15,
    }
}
