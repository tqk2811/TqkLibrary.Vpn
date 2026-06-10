namespace TqkLibrary.Vpn.Ipsec.Nat.Enums
{
    /// <summary>What a datagram received on UDP/4500 carries, per the Non-ESP Marker rule (RFC 3948 §2.2).</summary>
    public enum NatTPacketKind
    {
        /// <summary>Too short / unrecognisable.</summary>
        Invalid,

        /// <summary>An IKE message (prefixed with the 4-byte zero Non-ESP Marker).</summary>
        Ike,

        /// <summary>An ESP packet (first 4 bytes are a non-zero SPI).</summary>
        Esp,
    }
}
