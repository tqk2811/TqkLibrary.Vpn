using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Transport
{
    /// <summary>
    /// The production <see cref="ISshTransportFactory"/>: opens a real TCP byte stream (reusing the shared
    /// <see cref="TcpByteStream"/>) to the SSH server port. The one stream carries the whole SSH session. Mirrors
    /// <c>VtunSocketTransportFactory</c>.
    /// </summary>
    public sealed class SshSocketTransportFactory : ISshTransportFactory
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
