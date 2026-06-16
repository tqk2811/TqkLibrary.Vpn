using System.Buffers;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// The in-memory <see cref="Stream"/> that an <see cref="System.Net.Security.SslStream"/> runs on so TLS flows
    /// <em>inside</em> the OpenVPN control channel: writes from TLS are fragmented + sent reliably (the owner's write
    /// callback), and reads return the in-order payloads the owner delivers from the receive window. There is a single
    /// reader (the SslStream) so the inbound path is serialised; the owning <see cref="OpenVpnControlChannel"/> feeds it
    /// from its receive loop via <see cref="EnqueueInbound"/>.
    /// </summary>
    internal sealed class OpenVpnTlsBridgeStream : Stream
    {
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, Task> _writeTls;
        readonly object _gate = new();
        readonly Queue<byte[]> _inbound = new();
        byte[]? _partial;
        int _partialPos;
        bool _completed;
        TaskCompletionSource<bool>? _waiter;

        public OpenVpnTlsBridgeStream(Func<ReadOnlyMemory<byte>, CancellationToken, Task> writeTls)
        {
            _writeTls = writeTls;
        }

        /// <summary>Hands an in-order TLS record fragment to the reader (the SslStream). Empty inputs are ignored.</summary>
        public void EnqueueInbound(byte[] data)
        {
            if (data.Length == 0) return;
            TaskCompletionSource<bool>? toSignal;
            lock (_gate)
            {
                _inbound.Enqueue(data);
                toSignal = _waiter;
                _waiter = null;
            }
            toSignal?.TrySetResult(true);
        }

        /// <summary>Signals end-of-stream so a pending/next read returns 0 instead of blocking forever.</summary>
        public void CompleteInbound()
        {
            TaskCompletionSource<bool>? toSignal;
            lock (_gate)
            {
                _completed = true;
                toSignal = _waiter;
                _waiter = null;
            }
            toSignal?.TrySetResult(true);
        }

        async Task<int> ReadCoreAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                TaskCompletionSource<bool> tcs;
                lock (_gate)
                {
                    if (_partial is null && _inbound.Count > 0)
                    {
                        _partial = _inbound.Dequeue();
                        _partialPos = 0;
                    }
                    if (_partial is not null)
                    {
                        int n = Math.Min(count, _partial.Length - _partialPos);
                        Array.Copy(_partial, _partialPos, buffer, offset, n);
                        _partialPos += n;
                        if (_partialPos >= _partial.Length) _partial = null;
                        return n;
                    }
                    if (_completed) return 0;
                    _waiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    tcs = _waiter;
                }
                using (cancellationToken.Register(() => tcs.TrySetCanceled()))
                    await tcs.Task.ConfigureAwait(false);
            }
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadCoreAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadCoreAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _writeTls(new ReadOnlyMemory<byte>(buffer, offset, count), CancellationToken.None).GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _writeTls(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken);

#if NET5_0_OR_GREATER
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            byte[] tmp = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                int n = await ReadCoreAsync(tmp, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                new ReadOnlyMemory<byte>(tmp, 0, n).CopyTo(buffer);
                return n;
            }
            finally { ArrayPool<byte>.Shared.Return(tmp); }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => new ValueTask(_writeTls(buffer, cancellationToken));
#endif

        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
