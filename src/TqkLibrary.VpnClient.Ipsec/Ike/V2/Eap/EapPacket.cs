namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap
{
    /// <summary>
    /// Codec for a single EAP packet (RFC 3748 §4): <c>Code | Identifier | Length(2) | [Type | Type-Data]</c>.
    /// Success/Failure packets carry no Type/Type-Data. Shared by both directions of an EAP exchange.
    /// </summary>
    public static class EapPacket
    {
        /// <summary>
        /// Builds an EAP packet. Pass <paramref name="type"/> = null for Success/Failure (no Type/Type-Data);
        /// otherwise <paramref name="type"/> is the EAP method type (1 = Identity, 26 = MS-CHAPv2) and
        /// <paramref name="typeData"/> its payload.
        /// </summary>
        public static byte[] Build(EapCode code, byte identifier, byte? type, byte[] typeData)
        {
            int length = 4 + (type.HasValue ? 1 + typeData.Length : 0);
            byte[] packet = new byte[length];
            packet[0] = (byte)code;
            packet[1] = identifier;
            packet[2] = (byte)(length >> 8);
            packet[3] = (byte)length;
            if (type.HasValue)
            {
                packet[4] = type.Value;
                System.Buffer.BlockCopy(typeData, 0, packet, 5, typeData.Length);
            }
            return packet;
        }
    }
}
