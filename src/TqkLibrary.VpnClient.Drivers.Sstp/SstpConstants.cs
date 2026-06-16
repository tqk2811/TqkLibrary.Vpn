namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>Constants from [MS-SSTP].</summary>
    public static class SstpConstants
    {
        /// <summary>SSTP version (MUST be 0x10).</summary>
        public const byte Version = 0x10;

        /// <summary>The well-known SSTP_DUPLEX_POST request URI.</summary>
        public const string DuplexUri = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/";

        /// <summary>Encapsulated Protocol ID value for PPP.</summary>
        public const ushort EncapsulatedProtocolPpp = 0x0001;

        /// <summary>Hash-protocol bitmask bit: certificate hash via SHA-1.</summary>
        public const byte CertHashProtocolSha1 = 0x01;

        /// <summary>Hash-protocol bitmask bit: certificate hash via SHA-256.</summary>
        public const byte CertHashProtocolSha256 = 0x02;

        /// <summary>Length of the crypto-binding nonce.</summary>
        public const int NonceLength = 32;
    }
}
