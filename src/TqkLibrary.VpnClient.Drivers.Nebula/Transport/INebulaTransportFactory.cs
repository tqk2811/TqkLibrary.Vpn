using System.Net;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Transport
{
    /// <summary>
    /// Connects the UDP transport a Nebula session rides — one datagram is one Nebula packet (handshake / message /
    /// recv-error / lighthouse), so there is never any framing. The connection resolves the peer endpoint then asks the
    /// factory for a transport to it; the production factory opens a real UDP socket, an in-process factory returns a
    /// loopback so the whole driver can be driven offline. Mirrors <c>IWireGuardTransportFactory</c>.
    /// </summary>
    public interface INebulaTransportFactory
    {
        /// <summary>
        /// Connects a transport to <paramref name="remote"/> and returns it (with its inbound dispatch and the optional
        /// receive pump). The pump, when present, must be run by the caller on a task tied to the attempt lifetime.
        /// </summary>
        Task<NebulaTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
