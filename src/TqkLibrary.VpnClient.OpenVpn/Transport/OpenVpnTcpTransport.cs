using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// Adapts a reliable byte stream (<see cref="IByteStreamTransport"/> — TCP, or TCP+TLS via F.1) to the
    /// packet-oriented <see cref="IOpenVpnTransport"/> by applying OpenVPN's 16-bit length framing
    /// (<see cref="OpenVpnTcpFraming"/>). <see cref="SendAsync"/> length-prefixes and writes (serialised so concurrent
    /// sends never interleave a frame); <see cref="RunReceiveLoopAsync"/> reads the stream, reassembles whole packets
    /// and raises <see cref="DatagramReceived"/> for each. The UDP transport implements <see cref="IOpenVpnTransport"/>
    /// directly (one datagram already equals one packet) and needs no framing.
    /// </summary>
    public sealed class OpenVpnTcpTransport : IOpenVpnTransport
    {
        readonly IByteStreamTransport _stream;
        readonly OpenVpnTcpFraming _framing = new();
        readonly SemaphoreSlim _writeLock = new(1, 1);
        readonly int _readBufferSize;

        /// <summary>Wraps an established byte stream. <paramref name="readBufferSize"/> bounds one stream read.</summary>
        public OpenVpnTcpTransport(IByteStreamTransport stream, int readBufferSize = 4096)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            if (readBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(readBufferSize));
            _readBufferSize = readBufferSize;
        }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

        /// <inheritdoc/>
        public async Task SendAsync(ReadOnlyMemory<byte> packet)
        {
            byte[] framed = OpenVpnTcpFraming.Encode(packet.Span);
            await _writeLock.WaitAsync().ConfigureAwait(false);
            try { await _stream.WriteAsync(framed).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
        }

        /// <summary>
        /// Reads and dispatches packets until the stream closes (read returns 0) or cancellation. Run as a background
        /// task once the transport is connected.
        /// </summary>
        public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
        {
            byte[] buffer = new byte[_readBufferSize];
            while (!cancellationToken.IsCancellationRequested)
            {
                int read = await _stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) break; // peer closed the stream
                _framing.Append(buffer.AsSpan(0, read));
                while (_framing.TryReadPacket(out byte[] packet))
                    DatagramReceived?.Invoke(packet);
            }
        }
    }
}
