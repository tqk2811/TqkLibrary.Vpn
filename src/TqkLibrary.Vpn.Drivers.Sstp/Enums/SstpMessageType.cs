namespace TqkLibrary.Vpn.Drivers.Sstp.Enums
{
    /// <summary>SSTP control message types ([MS-SSTP] §2.2.2).</summary>
    public enum SstpMessageType : ushort
    {
        CallConnectRequest = 0x0001,
        CallConnectAck = 0x0002,
        CallConnectNak = 0x0003,
        CallConnected = 0x0004,
        CallAbort = 0x0005,
        CallDisconnect = 0x0006,
        CallDisconnectAck = 0x0007,
        EchoRequest = 0x0008,
        EchoResponse = 0x0009,
    }
}
