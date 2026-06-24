namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>Fixed values shared across the ZeroTier driver runtime (the protocol constants live in the ZeroTier project).</summary>
    public static class ZeroTierDriverConstants
    {
        /// <summary>The driver name tag used in the structured log lines and <see cref="ZeroTierDriver.Name"/>.</summary>
        public const string DriverName = "zerotier";

        /// <summary>Default ZeroTier UDP port (the port a node / controller listens on).</summary>
        public const int DefaultPort = 9993;

        /// <summary>
        /// Default overlay MTU. ZeroTier's virtual L2 supports up to 2800, but 2800 fragments on a 1500-byte path; the
        /// driver uses a conservative 1400 so the encapsulated Ethernet frame plus the VL1 + UDP/IP outer headers fit a
        /// typical path without fragmentation. The bridge subtracts the 14-byte Ethernet header when the stack binds.
        /// </summary>
        public const int DefaultMtu = 1400;

        /// <summary>The protocol version this client advertises in HELLO (ZeroTier 1.14–1.16 wire).</summary>
        public const byte ProtocolVersion = 13;

        /// <summary>Software major version advertised in HELLO.</summary>
        public const byte VersionMajor = 1;

        /// <summary>Software minor version advertised in HELLO.</summary>
        public const byte VersionMinor = 14;

        /// <summary>Default keepalive cadence (seconds) — a ZeroTier node pings paths roughly this often.</summary>
        public const int KeepAliveSeconds = 30;
    }
}
