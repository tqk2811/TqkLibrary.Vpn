namespace TqkLibrary.VpnClient.Abstractions.Transport.Interfaces
{
    /// <summary>
    /// An unreliable datagram pipe (UDP). Each send/receive is one datagram with preserved boundaries.
    /// IKE/ESP demultiplexing on UDP/4500 (RFC 3948) is done by the IPsec NAT-T layer
    /// (<c>Ipsec/Nat</c>: <c>NatTraversal</c>/<c>NatTraversalChannel</c>), not by a transport decorator.
    /// Kept as the base contract for a future DTLS datagram transport (roadmap F.3).
    /// </summary>
    public interface IDatagramTransport : IAsyncDisposable
    {
        /// <summary>Binds the local (ephemeral) socket and resolves the remote endpoint.</summary>
        ValueTask ConnectAsync(CancellationToken cancellationToken = default);

        /// <summary>Receives one datagram into <paramref name="buffer"/>; returns its length.</summary>
        ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);

        /// <summary>Sends <paramref name="datagram"/> as one datagram.</summary>
        ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default);
    }
}
