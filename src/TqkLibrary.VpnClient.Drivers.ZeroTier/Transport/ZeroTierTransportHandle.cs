using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Transport
{
    /// <summary>
    /// What an <see cref="IZeroTierTransportFactory"/> hands back: the UDP datagram pipe the VL1 handshake and data plane
    /// ride (<see cref="IDatagramTransport"/>), an inbound dispatch the connection wires to its packet handler, and the
    /// optional receive loop the connection pumps. A real socket needs a background receive loop
    /// (<see cref="ReceivePump"/>); an in-process loopback delivers itself by invoking the handler directly, so its pump
    /// is <c>null</c>. The pipe is disposed when the attempt ends. Mirrors <c>N2nTransportHandle</c>.
    /// </summary>
    public sealed class ZeroTierTransportHandle
    {
        /// <summary>Creates a handle around <paramref name="datagram"/>.</summary>
        public ZeroTierTransportHandle(IDatagramTransport datagram,
            Action<Action<ReadOnlyMemory<byte>>> setReceiver,
            Func<CancellationToken, Task>? receivePump = null)
        {
            Datagram = datagram ?? throw new ArgumentNullException(nameof(datagram));
            SetReceiver = setReceiver ?? throw new ArgumentNullException(nameof(setReceiver));
            ReceivePump = receivePump;
        }

        /// <summary>The UDP datagram pipe (the VL1 handshake + data ride this; one datagram = one VL1 packet).</summary>
        public IDatagramTransport Datagram { get; }

        /// <summary>Registers the connection's inbound-datagram handler with the transport.</summary>
        public Action<Action<ReadOnlyMemory<byte>>> SetReceiver { get; }

        /// <summary>The receive loop to run on a background task once the handler is wired; null for a self-pumping loopback.</summary>
        public Func<CancellationToken, Task>? ReceivePump { get; }
    }
}
