using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Transport
{
    /// <summary>
    /// The production <see cref="IVtunTransportFactory"/>: opens a real TCP byte stream (reusing the shared
    /// <see cref="TcpByteStream"/>) to the vtund control/data port. The one stream carries the auth handshake and the
    /// length-prefixed data frames. Mirrors <c>TincSocketTransportFactory</c> minus the UDP socket.
    /// </summary>
    public sealed class VtunSocketTransportFactory : IVtunTransportFactory
    {
        /// <inheritdoc/>
        public async Task<IByteStreamTransport> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            var stream = new TcpByteStream(remote);
            await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
            return stream;
        }
    }
}
