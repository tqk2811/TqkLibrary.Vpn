using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Transport
{
    /// <summary>
    /// Opens the TLS byte stream a SoftEther session rides — SoftEther is "Ethernet over HTTPS", so both the control
    /// handshake and the data session run over one reliable, ordered <see cref="IByteStreamTransport"/> (F.1). The
    /// production factory connects a real TCP socket and performs the TLS handshake; an in-process factory returns a
    /// loopback pipe so the whole driver can be driven offline. Mirrors <c>IWireGuardTransportFactory</c> /
    /// <c>IOpenVpnTransportFactory</c>, but byte-stream rather than datagram.
    /// </summary>
    public interface ISoftEtherTransportFactory
    {
        /// <summary>
        /// Connects a byte-stream transport to <paramref name="host"/>:<paramref name="port"/> and returns it (not yet
        /// <see cref="IByteStreamTransport.ConnectAsync"/>-ed unless the implementation does so eagerly). The connection
        /// calls <see cref="IByteStreamTransport.ConnectAsync"/> before the handshake.
        /// </summary>
        ValueTask<IByteStreamTransport> ConnectAsync(string host, int port, AddressFamilyPreference addressFamilyPreference, CancellationToken cancellationToken);
    }
}
