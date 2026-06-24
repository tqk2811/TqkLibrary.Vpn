namespace TqkLibrary.VpnClient.Nebula.Packet.Enums
{
    /// <summary>
    /// The Nebula packet sub-type (header byte 1). Its meaning depends on the <see cref="NebulaMessageType"/>: for a
    /// handshake it selects the variant (<see cref="HandshakeIxPsk0"/> — the only one, value 0, so the byte equals
    /// <see cref="None"/>); for data it is <see cref="None"/> or <see cref="MessageRelay"/>.
    /// </summary>
    public enum NebulaMessageSubType
    {
        /// <summary>Plain data, or the Noise IX handshake variant. Value 0.</summary>
        None = 0,

        /// <summary>Noise IX handshake (no PSK on the wire). Value 0 — the same byte as <see cref="None"/>.</summary>
        HandshakeIxPsk0 = 0,

        /// <summary>Relayed data sub-type (value 1).</summary>
        MessageRelay = 1,
    }
}
