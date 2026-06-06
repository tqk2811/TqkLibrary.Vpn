namespace TqkLibrary.Vpn.Transport.Udp
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

    /// <summary>
    /// UDP-encapsulation framing for IKE/ESP multiplexed on port 4500 (RFC 3948). IKE messages carry a leading
    /// 4-byte zero "Non-ESP Marker"; ESP packets do not (their first four bytes are the always-non-zero SPI).
    /// </summary>
    public static class NatTraversal
    {
        /// <summary>The IKE port; the first IKE_SA_INIT exchange happens here without a marker.</summary>
        public const int IkePort = 500;

        /// <summary>The NAT-T port; IKE (with marker) and UDP-encapsulated ESP share it.</summary>
        public const int NatTPort = 4500;

        /// <summary>Length of the Non-ESP Marker prefixed to IKE messages on port 4500.</summary>
        public const int MarkerLength = 4;

        /// <summary>Prepends the 4-byte Non-ESP Marker to an IKE message for sending on port 4500.</summary>
        public static byte[] WrapIke(ReadOnlySpan<byte> ikeMessage)
        {
            byte[] framed = new byte[MarkerLength + ikeMessage.Length];
            ikeMessage.CopyTo(framed.AsSpan(MarkerLength));
            return framed;
        }

        /// <summary>Classifies a datagram received on port 4500 as IKE, ESP, or invalid.</summary>
        public static NatTPacketKind Classify(ReadOnlySpan<byte> datagram)
        {
            if (datagram.Length < MarkerLength) return NatTPacketKind.Invalid;
            bool markerIsZero = datagram[0] == 0 && datagram[1] == 0 && datagram[2] == 0 && datagram[3] == 0;
            if (markerIsZero)
                return datagram.Length > MarkerLength ? NatTPacketKind.Ike : NatTPacketKind.Invalid;
            return NatTPacketKind.Esp;
        }

        /// <summary>Strips the Non-ESP Marker from a classified IKE datagram, returning the IKE message bytes.</summary>
        public static byte[] UnwrapIke(ReadOnlySpan<byte> datagram) => datagram.Slice(MarkerLength).ToArray();
    }
}
