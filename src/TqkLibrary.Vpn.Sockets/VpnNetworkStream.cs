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
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            _connection.Send(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer, offset, count, default).GetAwaiter().GetResult();

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
            => _connection.Send(buffer.AsSpan(offset, count));

        /// <inheritdoc/>
        public override void Flush() { }

        /// <inheritdoc/>
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

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
