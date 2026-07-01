using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TqkLibrary.VpnClient.Tailscale.Control
{
    /// <summary>
    /// Stream read helpers shared by the ts2021 control-channel readers
    /// (<see cref="TailscaleControlClient"/> map-response framing and <see cref="Ts2021Connector"/> handshake framing).
    /// </summary>
    internal static class StreamReadExtensions
    {
        /// <summary>
        /// Reads exactly <paramref name="destination"/>.Length bytes, looping until the buffer is full.
        /// Throws <see cref="EndOfStreamException"/> if the stream ends before the buffer is filled.
        /// </summary>
        public static async Task ReadExactlyAsync(this Stream stream, byte[] destination, CancellationToken cancellationToken)
        {
            int read = 0;
            while (read < destination.Length)
            {
                int n = await stream.ReadAsync(destination, read, destination.Length - read, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("Stream closed before the expected number of bytes was read.");
                read += n;
            }
        }
    }
}
