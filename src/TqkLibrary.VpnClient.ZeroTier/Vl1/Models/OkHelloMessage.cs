namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Models
{
    /// <summary>
    /// The decoded body of an <c>OK(HELLO)</c> reply. Every OK begins with the common header
    /// <c>inReVerb(1) || inRePacketId(8 BE)</c>; for an OK to a HELLO the verb-specific tail is
    /// <c>timestampEcho(8 BE) || protocolVersion(1) || versionMajor(1) || versionMinor(1) || versionRevision(2 BE) ||
    /// physicalDestination(InetAddress)</c>. The timestamp echoes exactly what the client put in its HELLO, which
    /// confirms the peer dearmored our packet; the physical destination is where the peer observed our HELLO arriving
    /// from (our public, NAT-reflected socket).
    /// </summary>
    public sealed class OkHelloMessage
    {
        /// <summary>The verb this OK answers (always <see cref="Enums.Vl1Verb.Hello"/> here).</summary>
        public byte InReVerb { get; set; }

        /// <summary>The packet ID of the HELLO this OK answers (echoes our HELLO's packet ID).</summary>
        public ulong InRePacketId { get; set; }

        /// <summary>The timestamp the peer echoes back from our HELLO (ms since the Unix epoch).</summary>
        public ulong TimestampEcho { get; set; }

        /// <summary>The peer's protocol version.</summary>
        public byte ProtocolVersion { get; set; }

        /// <summary>The peer's software major version.</summary>
        public byte VersionMajor { get; set; }

        /// <summary>The peer's software minor version.</summary>
        public byte VersionMinor { get; set; }

        /// <summary>The peer's software revision.</summary>
        public ushort VersionRevision { get; set; }

        /// <summary>The public socket the peer observed our HELLO arriving from (may be nil).</summary>
        public InetAddressValue PhysicalDestination { get; set; } = InetAddressValue.Nil;
    }
}
