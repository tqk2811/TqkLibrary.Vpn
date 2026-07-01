using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.GreInUdp
{
    /// <summary>
    /// Creates the (not-yet-connected) UDP datagram pipe that carries the GRE header for a GRE-in-UDP tunnel
    /// (RFC 8086, dst port 4754). A seam (instance behind an interface) so <see cref="GreInUdpConnection"/> can be
    /// unit-tested with a fake transport and no real socket — the default is <see cref="UdpGreTransportFactory"/>.
    /// Mirrors the way the IpEncap driver takes an <c>IRawIpTransportFactory</c>: the returned transport is opened later
    /// by the connection via <see cref="IDatagramTransport.ConnectAsync"/>.
    /// </summary>
    public interface IGreUdpTransportFactory
    {
        /// <summary>Creates a UDP datagram transport targeting <paramref name="remote"/> (host:4754). Not yet connected.</summary>
        IDatagramTransport Create(IPEndPoint remote);
    }
}
