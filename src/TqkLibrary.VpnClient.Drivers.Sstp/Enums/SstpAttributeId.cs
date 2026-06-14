namespace TqkLibrary.VpnClient.Drivers.Sstp.Enums
{
    /// <summary>SSTP attribute identifiers ([MS-SSTP] §2.2.3).</summary>
    public enum SstpAttributeId : byte
    {
        NoError = 0x00,
        EncapsulatedProtocolId = 0x01,
        StatusInfo = 0x02,
        CryptoBinding = 0x03,
        CryptoBindingReq = 0x04,
    }
}
