namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Wraps/unwraps a control-channel packet on the wire. The control channel encodes a plain control packet
    /// (<see cref="OpenVpnPacketCodec.EncodeControl"/>) then hands it to the wrap before sending; on receive it unwraps
    /// before <see cref="OpenVpnPacketCodec.TryDecodeControl"/>. Implementations: <see cref="OpenVpnTlsAuthWrap"/>
    /// (HMAC authenticate, <c>--tls-auth</c>) and <see cref="OpenVpnTlsCryptWrap"/> (authenticate + encrypt,
    /// <c>--tls-crypt</c>). When no wrap is configured the channel sends the encoded packet verbatim (the OpenVPN
    /// default with neither directive). Both methods are symmetric crypto — a client needs both (wrap its sends,
    /// unwrap the server's).
    /// </summary>
    public interface IOpenVpnControlWrap
    {
        /// <summary>Produces the wire bytes for an encoded control packet (adds the auth tag / encrypts).</summary>
        byte[] Wrap(byte[] controlPacket);

        /// <summary>
        /// Recovers the encoded control packet from wire bytes. Returns false if authentication fails or the framing is
        /// malformed (the caller drops the datagram).
        /// </summary>
        bool TryUnwrap(ReadOnlySpan<byte> wire, out byte[] controlPacket);
    }
}
