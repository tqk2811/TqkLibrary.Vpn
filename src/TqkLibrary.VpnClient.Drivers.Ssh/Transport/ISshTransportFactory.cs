using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Transport
{
    /// <summary>
    /// Connects the single TCP byte stream an SSH session rides — the SSH transport (handshake, KEX, auth, channel)
    /// multiplexes over this one connection. The production factory opens a real TCP socket; an in-process factory
    /// returns a loopback so the whole driver can be driven offline. Mirrors <c>IVtunTransportFactory</c>.
    /// </summary>
    public interface ISshTransportFactory
    {
        /// <summary>Connects a TCP byte stream to <paramref name="remote"/> and returns it (already connected).</summary>
        Task<IByteStreamTransport> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
