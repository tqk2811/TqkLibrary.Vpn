using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Transport
{
    /// <summary>
    /// What an <see cref="ITincTransportFactory"/> hands back: the <b>TCP meta-connection</b> byte stream
    /// (<see cref="Meta"/> — already connected; the SPTPS handshake and meta requests ride this) and the <b>UDP data
    /// plane</b> datagram pipe (<see cref="Datagram"/> — SPTPS data datagrams). The connection wires its inbound-datagram
    /// handler via <see cref="SetDatagramReceiver"/> and runs <see cref="DatagramReceivePump"/> on a background task for
    /// the attempt lifetime (null for a self-pumping loopback). Both pipes are disposed when the attempt ends. Mirrors
    /// <c>NebulaTransportHandle</c> but carries the extra meta stream.
    /// </summary>
    public sealed class TincTransportHandle
    {
        /// <summary>Creates a handle around the meta stream and the UDP datagram pipe.</summary>
        public TincTransportHandle(IByteStreamTransport meta, IDatagramTransport datagram,
            Action<Action<ReadOnlyMemory<byte>>> setDatagramReceiver,
            Func<CancellationToken, Task>? datagramReceivePump = null)
        {
            Meta = meta ?? throw new ArgumentNullException(nameof(meta));
            Datagram = datagram ?? throw new ArgumentNullException(nameof(datagram));
            SetDatagramReceiver = setDatagramReceiver ?? throw new ArgumentNullException(nameof(setDatagramReceiver));
            DatagramReceivePump = datagramReceivePump;
        }

        /// <summary>The connected TCP meta-connection (ID, SPTPS handshake, ACK, ADD_*, REQ_KEY/ANS_KEY ride this).</summary>
        public IByteStreamTransport Meta { get; }

        /// <summary>The UDP datagram pipe the data plane rides (one datagram = one SPTPS data record).</summary>
        public IDatagramTransport Datagram { get; }

        /// <summary>Registers the connection's inbound UDP-datagram handler with the transport.</summary>
        public Action<Action<ReadOnlyMemory<byte>>> SetDatagramReceiver { get; }

        /// <summary>The UDP receive loop to run on a background task once the handler is wired; null for a self-pumping loopback.</summary>
        public Func<CancellationToken, Task>? DatagramReceivePump { get; }
    }
}
