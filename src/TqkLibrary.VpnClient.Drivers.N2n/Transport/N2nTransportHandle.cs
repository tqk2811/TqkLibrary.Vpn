using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.N2n.Transport
{
    /// <summary>
    /// What an <see cref="IN2nTransportFactory"/> hands back: the UDP datagram pipe the registration and data plane ride
    /// (<see cref="IDatagramTransport"/>), an inbound dispatch the connection wires to its packet handler, and the
    /// optional receive loop the connection pumps. A real socket needs a background receive loop
    /// (<see cref="ReceivePump"/>); an in-process loopback delivers itself by invoking the handler directly, so its pump
    /// is <c>null</c>. The pipe is disposed when the attempt ends. Mirrors <c>NebulaTransportHandle</c>.
    /// </summary>
    public sealed class N2nTransportHandle
    {
        /// <summary>Creates a handle around <paramref name="datagram"/>.</summary>
        public N2nTransportHandle(IDatagramTransport datagram,
            Action<Action<ReadOnlyMemory<byte>>> setReceiver,
            Func<CancellationToken, Task>? receivePump = null)
        {
            Datagram = datagram ?? throw new ArgumentNullException(nameof(datagram));
            SetReceiver = setReceiver ?? throw new ArgumentNullException(nameof(setReceiver));
            ReceivePump = receivePump;
        }

        /// <summary>The UDP datagram pipe (registration + data ride this; one datagram = one n2n message).</summary>
        public IDatagramTransport Datagram { get; }

        /// <summary>Registers the connection's inbound-datagram handler with the transport.</summary>
        public Action<Action<ReadOnlyMemory<byte>>> SetReceiver { get; }

        /// <summary>The receive loop to run on a background task once the handler is wired; null for a self-pumping loopback.</summary>
        public Func<CancellationToken, Task>? ReceivePump { get; }
    }
}
