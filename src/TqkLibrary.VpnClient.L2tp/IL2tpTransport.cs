namespace TqkLibrary.VpnClient.L2tp
{
    /// <summary>
    /// Carries raw L2TP messages (the bytes that sit inside the UDP/1701 payload). The L2TP/IPsec driver implements
    /// this over ESP-protected UDP; an in-process pair implements it for tests.
    /// </summary>
    public interface IL2tpTransport
    {
        /// <summary>Sends one L2TP message (control or data) as a single datagram.</summary>
        Task SendAsync(ReadOnlyMemory<byte> l2tpDatagram);

        /// <summary>Raised for each inbound L2TP message.</summary>
        event Action<ReadOnlyMemory<byte>>? DatagramReceived;
    }
}
