using TqkLibrary.VpnClient.Nebula.Packet.Enums;

namespace TqkLibrary.VpnClient.Nebula.Packet.Models
{
    /// <summary>
    /// The 16-byte Nebula packet header (header.go), big-endian. Layout:
    /// byte 0 = <c>Version&lt;&lt;4 | (Type &amp; 0x0F)</c>, byte 1 = SubType, bytes 2-3 = Reserved (uint16),
    /// bytes 4-7 = RemoteIndex (uint32 — the peer's session index), bytes 8-15 = MessageCounter (uint64).
    /// </summary>
    public sealed class NebulaHeader
    {
        /// <summary>The header length on the wire (always 16 bytes).</summary>
        public const int Size = 16;

        /// <summary>Protocol version (currently 1).</summary>
        public byte Version { get; set; } = 1;

        /// <summary>Packet type (low nibble of byte 0).</summary>
        public NebulaMessageType Type { get; set; }

        /// <summary>Packet sub-type (byte 1).</summary>
        public byte SubType { get; set; }

        /// <summary>Reserved (bytes 2-3), zero on send.</summary>
        public ushort Reserved { get; set; }

        /// <summary>The recipient's session index the packet is routed to (bytes 4-7).</summary>
        public uint RemoteIndex { get; set; }

        /// <summary>The per-session message counter / nonce (bytes 8-15).</summary>
        public ulong MessageCounter { get; set; }
    }
}
