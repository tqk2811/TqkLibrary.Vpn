using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Transport
{
    /// <summary>
    /// The production <see cref="ITincTransportFactory"/>: opens a real TCP meta-connection (reusing the shared
    /// <see cref="TcpByteStream"/>) and a connected UDP data socket to the tinc peer, both to the same endpoint. The TCP
    /// stream carries the SPTPS handshake and meta requests; the UDP socket carries SPTPS data datagrams (one datagram =
    /// one record). Mirrors <c>NebulaSocketTransportFactory</c>'s UDP socket, plus the meta stream.
    /// </summary>
    public sealed class TincSocketTransportFactory : ITincTransportFactory
    {
        readonly int _receiveBufferSize;

        /// <summary>Creates the factory. <paramref name="receiveBufferSize"/> bounds one UDP datagram read (default 65535).</summary>
        public TincSocketTransportFactory(int receiveBufferSize = 65535)
        {
            if (receiveBufferSize < 1) throw new ArgumentOutOfRangeException(nameof(receiveBufferSize));
            _receiveBufferSize = receiveBufferSize;
        }

        /// <inheritdoc/>
        public async Task<TincTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));

            var meta = new TcpByteStream(remote);
            await meta.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var udp = new UdpDatagramSocket(remote, _receiveBufferSize);
            await udp.ConnectAsync(cancellationToken).ConfigureAwait(false);

            return new TincTransportHandle(meta, udp, udp.SetReceiver, udp.RunReceiveLoopAsync);
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only; mirrors the Nebula driver's UDP socket).</summary>
        sealed class UdpDatagramSocket : IDatagramTransport
        {
            readonly IPEndPoint _remote;
            readonly int _receiveBufferSize;
            readonly UdpClient _client;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public UdpDatagramSocket(IPEndPoint remote, int receiveBufferSize)
            {
                _remote = remote;
                _receiveBufferSize = receiveBufferSize;
                _client = new UdpClient(remote.AddressFamily);
            }

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                _client.Connect(_remote); // sets the default peer; sends/receives are then connection-style
                return default;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return new ValueTask(_client.Client.SendAsync(datagram, SocketFlags.None, cancellationToken).AsTask());
#else
                byte[] copy = datagram.ToArray();
                return new ValueTask(_client.SendAsync(copy, copy.Length)); // connected ⇒ no endpoint
#endif
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return await _client.Client.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
#else
                using (cancellationToken.Register(() => { try { _client.Dispose(); } catch { } }))
                {
                    UdpReceiveResult result = await _client.ReceiveAsync().ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = Math.Min(result.Buffer.Length, buffer.Length);
                    result.Buffer.AsMemory(0, n).CopyTo(buffer);
                    return n;
                }
#endif
            }

            /// <summary>Reads and dispatches datagrams to the wired handler until cancellation (UDP has no end-of-stream).</summary>
            public async Task RunReceiveLoopAsync(CancellationToken cancellationToken = default)
            {
                byte[] buffer = new byte[_receiveBufferSize];
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        int read = await ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (read <= 0) continue; // a 0-length datagram is not a close on UDP — keep listening
                        _receiver?.Invoke(buffer.AsSpan(0, read).ToArray());
                    }
                }
                catch (OperationCanceledException) { } // cancellation is the normal way this loop ends
            }

            public ValueTask DisposeAsync()
            {
                try { _client.Dispose(); } catch { }
                return default;
            }
        }
    }
}
