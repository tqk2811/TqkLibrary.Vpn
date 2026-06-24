namespace TqkLibrary.VpnClient.Drivers.N2n
{
    /// <summary>Fixed values shared across the n2n driver runtime (the protocol constants live in <c>N2n.Wire.N2nConstants</c>).</summary>
    public static class N2nDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and the <see cref="N2nDriver.Name"/>.</summary>
        public const string DriverName = "n2n";

        /// <summary>Default supernode UDP port (<c>N2N_EDGE_SN_HOST_PORT</c>).</summary>
        public const int DefaultSupernodePort = 7654;

        /// <summary>
        /// Default tunnel MTU. n2n's default edge MTU is 1290 (it leaves room for the UDP/IP outer header plus the n2n
        /// PACKET header so the encapsulated Ethernet frame never fragments on a 1500-byte path).
        /// </summary>
        public const int DefaultMtu = 1290;

        /// <summary>Default registration lifetime (seconds) the edge assumes when the supernode does not advertise one.</summary>
        public const ushort DefaultRegistrationLifetimeSeconds = 60;
    }
}
