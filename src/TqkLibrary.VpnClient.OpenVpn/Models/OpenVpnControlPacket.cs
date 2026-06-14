using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn.Models
{
    /// <summary>
    /// A decoded OpenVPN control-channel packet (P_CONTROL_*, the HARD/SOFT resets, or P_ACK_V1). The reliability
    /// layer reads <see cref="PacketId"/> for ordering/dedup and <see cref="AckPacketIds"/> for clearing the send
    /// window; <see cref="Payload"/> is the TLS record fragment a P_CONTROL carries (empty on resets/acks).
    /// </summary>
    public sealed class OpenVpnControlPacket
    {
        /// <summary>The packet opcode (high 5 bits of the first byte).</summary>
        public OpenVpnOpcode Opcode { get; set; }

        /// <summary>The key-id (low 3 bits of the first byte); selects among up to 8 overlapping key generations.</summary>
        public byte KeyId { get; set; }

        /// <summary>The sender's 64-bit session id.</summary>
        public ulong SessionId { get; set; }

        /// <summary>The packet-ids this packet acknowledges (0–8). Empty when nothing is being acked.</summary>
        public IReadOnlyList<uint> AckPacketIds { get; set; } = Array.Empty<uint>();

        /// <summary>The peer's session id, present on the wire only when <see cref="AckPacketIds"/> is non-empty.</summary>
        public ulong RemoteSessionId { get; set; }

        /// <summary>This packet's own reliability packet-id. Not present on P_ACK_V1 (which only acknowledges).</summary>
        public uint PacketId { get; set; }

        /// <summary>The TLS record fragment carried by a P_CONTROL/reset (empty for resets and P_ACK_V1).</summary>
        public byte[] Payload { get; set; } = Array.Empty<byte>();

        /// <summary>True for P_ACK_V1, which carries acknowledgements only — no own packet-id and no payload.</summary>
        public bool IsAckOnly => Opcode == OpenVpnOpcode.AckV1;
    }
}
