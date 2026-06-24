using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Transport
{
    /// <summary>
    /// Connects the single TCP byte stream a vtun session rides — the same connection carries the authentication
    /// handshake and then the length-prefixed data frames (vtun <c>proto tcp</c>). The production factory opens a real
    /// TCP socket; an in-process factory returns a loopback so the whole driver can be driven offline. Mirrors
    /// <c>ITincTransportFactory</c> but yields a single stream (vtun has no separate UDP data plane in tcp mode).
    /// </summary>
    public interface IVtunTransportFactory
    {
        /// <summary>Connects a TCP byte stream to <paramref name="remote"/> and returns it (already connected).</summary>
        Task<IByteStreamTransport> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken);
    }
}
