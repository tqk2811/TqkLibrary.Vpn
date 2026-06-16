namespace TqkLibrary.VpnClient.Ppp.Enums
{
    /// <summary>IPCP configuration option types (RFC 1332 + RFC 1877 DNS/NBNS extensions).</summary>
    public enum IpcpOptionType : byte
    {
        /// <summary>IP-Addresses (deprecated).</summary>
        IpAddresses = 1,

        /// <summary>IP-Compression-Protocol (Van Jacobson).</summary>
        IpCompressionProtocol = 2,

        /// <summary>IP-Address — request your tunnel IP (send 0.0.0.0; server returns it via Configure-Nak).</summary>
        IpAddress = 3,

        /// <summary>Primary DNS server (RFC 1877).</summary>
        PrimaryDns = 129,

        /// <summary>Primary NBNS/WINS server (RFC 1877).</summary>
        PrimaryNbns = 130,

        /// <summary>Secondary DNS server (RFC 1877).</summary>
        SecondaryDns = 131,

        /// <summary>Secondary NBNS/WINS server (RFC 1877).</summary>
        SecondaryNbns = 132,
    }
}
