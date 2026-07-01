namespace TqkLibrary.VpnClient.Abstractions.Net
{
    /// <summary>
    /// Well-known IANA IP protocol numbers (the IPv4 Protocol / IPv6 Next-Header field), shared so that raw-IP
    /// drivers and codecs reference one authoritative set instead of re-declaring the constants. Placed in
    /// Abstractions (which every driver already references) so reusing it adds no new project dependency.
    /// </summary>
    public static class IpProtocol
    {
        /// <summary>ICMP for IPv4 (RFC 792).</summary>
        public const byte Icmp = 1;

        /// <summary>IPv4-in-IPv4 encapsulation (RFC 2003).</summary>
        public const byte IpInIp = 4;

        /// <summary>TCP (RFC 793).</summary>
        public const byte Tcp = 6;

        /// <summary>UDP (RFC 768).</summary>
        public const byte Udp = 17;

        /// <summary>IPv6 encapsulation — 6in4 / SIT (RFC 4213); also the IPv6 header protocol number.</summary>
        public const byte Ipv6 = 41;

        /// <summary>IPv6 Fragment extension header (RFC 8200).</summary>
        public const byte Fragment = 44;

        /// <summary>Generic Routing Encapsulation (RFC 2784/2890).</summary>
        public const byte Gre = 47;

        /// <summary>IPsec Encapsulating Security Payload (RFC 4303).</summary>
        public const byte Esp = 50;

        /// <summary>ICMP for IPv6 (RFC 4443).</summary>
        public const byte Icmpv6 = 58;

        /// <summary>"No Next Header" marker (RFC 8200 / RFC 4303 §2.6 dummy packet).</summary>
        public const byte NoNextHeader = 59;
    }
}
