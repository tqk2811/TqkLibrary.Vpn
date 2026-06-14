namespace TqkLibrary.VpnClient.Ppp.Enums
{
    /// <summary>LCP configuration option types (RFC 1661 §6, RFC 1570).</summary>
    public enum LcpOptionType : byte
    {
        /// <summary>Maximum-Receive-Unit.</summary>
        Mru = 1,

        /// <summary>Authentication-Protocol (e.g. 0xC223 CHAP + algorithm 0x81 for MS-CHAPv2).</summary>
        AuthenticationProtocol = 3,

        /// <summary>Quality-Protocol.</summary>
        QualityProtocol = 4,

        /// <summary>Magic-Number.</summary>
        MagicNumber = 5,

        /// <summary>Protocol-Field-Compression.</summary>
        ProtocolFieldCompression = 7,

        /// <summary>Address-and-Control-Field-Compression.</summary>
        AddressControlFieldCompression = 8,
    }
}
