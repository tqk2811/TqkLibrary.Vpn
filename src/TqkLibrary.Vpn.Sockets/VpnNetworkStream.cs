using System.IO;
using TqkLibrary.Vpn.IpStack.Tcp;

namespace TqkLibrary.Vpn.Sockets
{
    /// <summary>A <see cref="Stream"/> over a userspace <see cref="TcpConnection"/>, suitable for HttpClient.</summary>
    public sealed class VpnNetworkStream : Stream
    {
        readonly TcpConnection _connection;

        internal VpnNetworkStream(TcpConnection connection) => _connection = connection;

        /// <inheritdoc/>
        public override bool CanRead => true;

        /// <inheritdoc/>
        public override bool CanWrite => true;

        /// <inheritdoc/>
        public override bool CanSeek => false;

        /// <inheritdoc/>
        public override long Length => throw new NotSupportedException();

        /// <inheritdoc/>
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        /// <inheritdoc/>
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _connection.ReadAsync(buffer, offset, count, cancellationToken);

        /// <inheritdoc/>
        /// <remarks>Backpressured + error-propagating: awaits the peer window when the send buffer is full, throws <see cref="IOException"/> if the connection has faulted/closed.</remarks>
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _connection.SendAsync(buffer.AsMemory(offset, count), cancellationToken);

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer, offset, count, default).GetAwaiter().GetResult();

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
            => _connection.SendAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

        /// <inheritdoc/>
        public override void Flush()
            => _connection.SendAsync(ReadOnlyMemory<byte>.Empty).GetAwaiter().GetResult();

        /// <inheritdoc/>
        /// <remarks>Surfaces a pending fault (RST / give-up) to the caller; the data is already in the TCP send buffer, so it does not block on ACKs.</remarks>
        public override Task FlushAsync(CancellationToken cancellationToken)
            => _connection.SendAsync(ReadOnlyMemory<byte>.Empty, cancellationToken);

        /// <inheritdoc/>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <inheritdoc/>
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing) _connection.CloseSend();
            base.Dispose(disposing);
        }
    }
}
