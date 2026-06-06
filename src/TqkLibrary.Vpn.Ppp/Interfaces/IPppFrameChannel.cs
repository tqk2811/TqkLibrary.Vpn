namespace TqkLibrary.Vpn.Ppp.Interfaces
{
    /// <summary>
    /// A bidirectional channel carrying complete PPP frames (Address+Control+Protocol+Information). The byte
    /// transport below (HDLC over SSTP, or packet-mode over L2TP) is abstracted away from the PPP engine.
    /// </summary>
    public interface IPppFrameChannel
    {
        /// <summary>Sends one PPP frame toward the peer.</summary>
        ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default);

        /// <summary>Raised for each inbound PPP frame.</summary>
        event Action<ReadOnlyMemory<byte>>? FrameReceived;
    }
}
