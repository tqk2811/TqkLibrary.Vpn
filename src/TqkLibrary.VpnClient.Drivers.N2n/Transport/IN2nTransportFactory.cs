using System.Net;

namespace TqkLibrary.VpnClient.Drivers.N2n.Transport
{
    /// <summary>
    /// Connects the UDP transport an n2n edge rides to its supernode — one datagram is one n2n message (REGISTER_SUPER /
    /// REGISTER_SUPER_ACK / PACKET / REGISTER / PEER_INFO), so there is never any framing. The connection resolves the
    /// supernode endpoint then asks the factory for a transport to it; the production factory opens a real UDP socket, an
    /// in-process factory returns a loopback so the whole driver can be driven offline. Mirrors
    /// <c>INebulaTransportFactory</c>.
    /// </summary>
    public interface IN2nTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> (the supernode) and returns it (with its inbound dispatch
        /// and the optional receive pump). The pump, when present, must be run by the caller on a task tied to the
        /// attempt lifetime.
        /// </summary>
        Task<N2nTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
