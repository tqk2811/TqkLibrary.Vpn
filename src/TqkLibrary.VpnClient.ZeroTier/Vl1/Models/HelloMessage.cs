using TqkLibrary.VpnClient.ZeroTier.Identity.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Models
{
    /// <summary>
    /// The body of a VL1 <c>HELLO</c> verb — the first message a node sends to introduce itself before a session key
    /// exists. Because no key is shared yet, HELLO is carried Poly1305-only (the cipher field is
    /// <c>Poly1305None</c>) and its MAC key is derived from the static identity agreement.
    /// <para>
    /// Body layout (after the verb byte): protocol version (1), major (1), minor (1), revision (2, big-endian),
    /// timestamp (8, big-endian, ms) then the sender's serialized identity (address + type + public key).
    /// </para>
    /// </summary>
    public sealed class HelloMessage
    {
        /// <summary>VL1 protocol version this client speaks.</summary>
        public byte ProtocolVersion { get; set; }

        /// <summary>Software major version.</summary>
        public byte VersionMajor { get; set; }

        /// <summary>Software minor version.</summary>
        public byte VersionMinor { get; set; }

        /// <summary>Software revision (build).</summary>
        public ushort VersionRevision { get; set; }

        /// <summary>Sender timestamp in milliseconds since the Unix epoch.</summary>
        public ulong Timestamp { get; set; }

        /// <summary>The sender's identity (address + 64-byte public key).</summary>
        public ZeroTierIdentity Identity { get; set; } = new ZeroTierIdentity();
    }
}
