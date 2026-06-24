using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ssh.Tests
{
    /// <summary>A bidirectional in-memory byte-stream pair for offline tests (see the identical helper in the Ssh tests).</summary>
    public sealed class LoopbackByteStream : IByteStreamTransport
    {
        sealed class Pipe
        {
            public readonly Queue<byte> Bytes = new();
            public readonly object Lock = new();
            public readonly SemaphoreSlim Signal = new(0, int.MaxValue);
        }

        readonly Pipe _readPipe;
        readonly Pipe _writePipe;

        LoopbackByteStream(Pipe readPipe, Pipe writePipe)
        {
            _readPipe = readPipe;
            _writePipe = writePipe;
        }

        /// <summary>Creates two connected endpoints (A↔B).</summary>
        public static (LoopbackByteStream a, LoopbackByteStream b) CreatePair()
        {
            var p1 = new Pipe();
            var p2 = new Pipe();
            return (new LoopbackByteStream(p1, p2), new LoopbackByteStream(p2, p1));
        }

        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                lock (_readPipe.Lock)
                {
                    if (_readPipe.Bytes.Count > 0)
                    {
                        int n = 0;
                        while (n < buffer.Length && _readPipe.Bytes.Count > 0) buffer.Span[n++] = _readPipe.Bytes.Dequeue();
                        return n;
                    }
                }
                await _readPipe.Signal.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (_writePipe.Lock)
            {
                foreach (byte b in buffer.Span) _writePipe.Bytes.Enqueue(b);
            }
            _writePipe.Signal.Release();
            return default;
        }

        public ValueTask DisposeAsync() => default;
    }
}
