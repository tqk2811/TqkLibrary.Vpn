using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// Adapts an unreliable datagram pipe (<see cref="IDatagramTransport"/> — UDP) to the packet-oriented
    /// <see cref="IOpenVpnTransport"/>. On UDP one datagram already equals one OpenVPN packet, so — unlike
    /// <see cref="OpenVpnTcpTransport"/> — there is no length framing: <see cref="SendAsync"/> writes the packet as a
    /// single datagram and <see cref="RunReceiveLoopAsync"/> raises <see cref="DatagramReceived"/> once per datagram
    /// read. A zero-length read is not end-of-stream (UDP has no close), so the loop simply keeps listening; it ends only
    /// on cancellation. This is the UDP sibling of the TCP transport built in V2.g.
    /// </summary>
    public sealed class OpenVpnUdpTransport : IOpenVpnTransport
    {
        readonly IDatagramTransport _datagram;
        readonly int _receiveBufferSize;

        /// <summary>
        /// Wraps an established datagram pipe. <paramref name="receiveBufferSize"/> bounds one datagram read (default
        /// 65535 — the largest possible UDP payload, so a packet is never truncated).
        /// </summary>
        public OpenVpnUdpTransport(IDatagramTransport datagram, int receiveBufferSize = 65535)
        {
            _datagram = datagram ?? throw new ArgumentNullException(nameof(datagram));
            if (receiveBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(receiveBufferSize));
            _receiveBufferSize = receiveBufferSize;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

        /// <inheritdoc/>
        public Task SendAsync(ReadOnlyMemory<byte> packet)
            => _datagram.SendAsync(packet).AsTask(); // one OpenVPN packet = one UDP datagram, no length framing

        /// <summary>
        /// Reads and dispatches datagrams until cancellation (which ends the loop cleanly — UDP has no end-of-stream).
        /// Run as a background task once the transport is connected; each datagram is delivered as one OpenVPN packet
        /// (copied out of the reused read buffer).
        /// </summary>
        public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
        {
            byte[] buffer = new byte[_receiveBufferSize];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int read = await _datagram.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read <= 0) continue; // a 0-length datagram is not a close on UDP — keep listening
                    DatagramReceived?.Invoke(buffer.AsSpan(0, read).ToArray());
                }
            }
            catch (OperationCanceledException) { } // cancellation is the normal way this loop ends
        }
    }
}
