using System.Collections.Concurrent;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Vtun.Transport;

namespace TqkLibrary.VpnClient.Drivers.Vtun.Tests
{
    /// <summary>
    /// An in-process bidirectional byte pipe standing in for the vtun TCP connection, plus the factory that hands the
    /// client end to a real <see cref="VtunConnection"/>. Throwaway test scaffolding — the library is a client; the
    /// server role exists only in <see cref="SimulatedVtunServer"/>. Mirrors the tinc driver's loopback harness.
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

    /// <summary>An <see cref="IVtunTransportFactory"/> handing back a fixed in-process client byte stream.</summary>
    sealed class InProcessVtunTransportFactory : IVtunTransportFactory
    {
        readonly IByteStreamTransport _client;
        public InProcessVtunTransportFactory(IByteStreamTransport client) => _client = client;

        public Task<IByteStreamTransport> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(_client);
    }
}
