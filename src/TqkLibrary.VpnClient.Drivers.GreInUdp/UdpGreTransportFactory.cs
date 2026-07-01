using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GreInUdp
{
    /// <summary>
    /// The production <see cref="IGreUdpTransportFactory"/>: hands out a real connected UDP socket
    /// (<see cref="UdpDatagramTransport"/>) to carry the GRE header for a GRE-in-UDP tunnel (RFC 8086, dst port 4754).
    /// Needs no elevation and no raw IP socket — GRE-in-UDP rides an ordinary UDP datagram pipe.
    /// </summary>
    public sealed class UdpGreTransportFactory : IGreUdpTransportFactory
    {
        readonly IPAddress? _localBind;

        /// <summary>Creates the factory. <paramref name="localBind"/> optionally pins the local source address (null → any).</summary>
        public UdpGreTransportFactory(IPAddress? localBind = null)
        {
            _localBind = localBind;
        }

        /// <inheritdoc/>
        public IDatagramTransport Create(IPEndPoint remote) => new UdpDatagramTransport(remote, _localBind);
    }
}
