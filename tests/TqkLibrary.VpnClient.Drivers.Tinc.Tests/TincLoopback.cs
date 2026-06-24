using System.Collections.Concurrent;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Tinc.Transport;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Tests
{
    /// <summary>
    /// In-process loopback transports for driving the real <see cref="TincConnection"/> against an in-process tinc
    /// responder. A bidirectional byte pipe stands in for the TCP meta-connection; a self-pumping datagram pipe stands
    /// in for the UDP data plane. Throwaway test scaffolding — the library is a client; the responder role exists only
    /// in <see cref="SimulatedTincResponder"/>. Mirrors the Nebula driver's loopback harness.
    /// </summary>
    sealed class ByteStreamPipe
    {
        readonly BlockingCollection<byte[]> _toClient = new();
        readonly BlockingCollection<byte[]> _toServer = new();

        public IByteStreamTransport ClientSide => new End(_toServer, _toClient); // client writes→toServer, reads←toClient
        public IByteStreamTransport ServerSide => new End(_toClient, _toServer);

        sealed class End : IByteStreamTransport
        {
            readonly BlockingCollection<byte[]> _out;
            readonly BlockingCollection<byte[]> _in;
            byte[] _residual = Array.Empty<byte>();
            int _residualOffset;

            public End(BlockingCollection<byte[]> outBox, BlockingCollection<byte[]> inBox) { _out = outBox; _in = inBox; }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _out.Add(buffer.ToArray(), cancellationToken);
                return default;
            }

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_residualOffset >= _residual.Length)
                {
                    // Block (off the calling thread) until a chunk arrives or cancellation.
                    _residual = await Task.Run(() =>
                    {
                        try { return _in.Take(cancellationToken); }
                        catch (OperationCanceledException) { return Array.Empty<byte>(); }
                        catch (InvalidOperationException) { return Array.Empty<byte>(); } // completed
                    }, cancellationToken).ConfigureAwait(false);
                    _residualOffset = 0;
                    if (_residual.Length == 0) return 0;
                }
                int n = Math.Min(buffer.Length, _residual.Length - _residualOffset);
                _residual.AsMemory(_residualOffset, n).CopyTo(buffer);
                _residualOffset += n;
                return n;
            }

            public ValueTask DisposeAsync() { try { _out.CompleteAdding(); } catch { } return default; }
        }
    }

    /// <summary>A self-pumping in-memory datagram pipe (one end per peer), delivering each send to the peer in order.</summary>
    sealed class DatagramPipe
    {
        public End Client { get; }
        public End Server { get; }

        public DatagramPipe()
        {
            Client = new End();
            Server = new End();
            Client.Peer = Server;
            Server.Peer = Client;
        }

        public sealed class End : IDatagramTransport
        {
            public End? Peer;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;
            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                End? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer._receiver?.Invoke(copy), TaskScheduler.Default);
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => throw new NotSupportedException("The loopback datagram pipe self-pumps via the registered receiver.");

            public ValueTask DisposeAsync() => default;
        }
    }

    /// <summary>An <see cref="ITincTransportFactory"/> handing back fixed in-process meta + datagram pipes.</summary>
    sealed class InProcessTincTransportFactory : ITincTransportFactory
    {
        readonly IByteStreamTransport _meta;
        readonly DatagramPipe.End _udp;

        public InProcessTincTransportFactory(IByteStreamTransport meta, DatagramPipe.End udp) { _meta = meta; _udp = udp; }

        public Task<TincTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new TincTransportHandle(_meta, _udp, _udp.SetReceiver, datagramReceivePump: null));
    }
}
