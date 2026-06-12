using System.Security.Cryptography.X509Certificates;
using TqkLibrary.Vpn.Drivers.Sstp;
using TqkLibrary.Vpn.Drivers.Sstp.Transport;
using Xunit;

namespace TqkLibrary.Vpn.Sstp.Tests
{
    /// <summary>
    /// Offline coverage for the P1.5 transport read-timeout: a stalled server (TLS open, no bytes arriving) surfaces as
    /// a <see cref="TimeoutException"/> from <see cref="SstpTransport.ReadPacketAsync"/> instead of blocking forever,
    /// while caller cancellation and timely data are unaffected. Uses a fake stream that *blocks* (not returns 0) when
    /// its inbound buffer is empty, so the read genuinely waits the way a live-but-stalled TLS stream would.
    /// </summary>
    public class SstpTransportTimeoutTests
    {
        [Fact]
        public void Default_ReadTimeoutIsInfinite()
            => Assert.Equal(Timeout.InfiniteTimeSpan, new SstpTransportOptions().ReadTimeout);

        [Fact]
        public async Task ReadPacket_ServerStalls_ThrowsTimeout()
        {
            var stream = new ProgrammableTlsByteStream { BlockWhenEmpty = true };
            using var transport = new SstpTransport(stream, options: new SstpTransportOptions { ReadTimeout = TimeSpan.FromMilliseconds(50) });

            await Assert.ThrowsAsync<TimeoutException>(() => transport.ReadPacketAsync());
        }

        [Fact]
        public async Task ReadPacket_DataArrivesBeforeTimeout_Succeeds()
        {
            // Frame a data packet with one transport, then replay its bytes into a timeout-guarded reader.
            var writeStream = new ProgrammableTlsByteStream();
            using (var writer = new SstpTransport(writeStream))
                await writer.SendDataAsync(new byte[] { 9, 8, 7, 6 });

            var readStream = new ProgrammableTlsByteStream { BlockWhenEmpty = true };
            readStream.EnqueueInbound(writeStream.Outbound.ToArray());
            using var transport = new SstpTransport(readStream, options: new SstpTransportOptions { ReadTimeout = TimeSpan.FromSeconds(10) });

            (bool isControl, byte[] body) = await transport.ReadPacketAsync();

            Assert.False(isControl);
            Assert.Equal(new byte[] { 9, 8, 7, 6 }, body);
        }

        [Fact]
        public async Task ReadPacket_CallerCancels_IsCanceled_NotTimedOut()
        {
            var stream = new ProgrammableTlsByteStream { BlockWhenEmpty = true };
            using var transport = new SstpTransport(stream, options: new SstpTransportOptions { ReadTimeout = TimeSpan.FromSeconds(10) });
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

            // Caller cancellation must propagate as OperationCanceledException, never be reclassified as a timeout.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => transport.ReadPacketAsync(cts.Token));
        }

        /// <summary>
        /// An in-memory <see cref="ITlsByteStream"/> that records writes and replays scripted inbound bytes; when the
        /// inbound buffer is empty it either returns 0 (closed) or — with <see cref="BlockWhenEmpty"/> — blocks until the
        /// read token is cancelled, modelling a live TLS stream that has stalled.
        /// </summary>
        sealed class ProgrammableTlsByteStream : ITlsByteStream
        {
            readonly Queue<byte> _inbound = new();

            public List<byte> Outbound { get; } = new();
            public bool BlockWhenEmpty { get; set; }
            public X509Certificate2? RemoteCertificate => null;

            public void EnqueueInbound(byte[] bytes)
            {
                foreach (byte b in bytes) _inbound.Enqueue(b);
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_inbound.Count == 0)
                {
                    if (BlockWhenEmpty)
                        await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false); // unblocks only on cancellation
                    return 0;
                }
                int n = 0;
                while (n < buffer.Length && _inbound.Count > 0) buffer.Span[n++] = _inbound.Dequeue();
                return n;
            }

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                Outbound.AddRange(buffer.ToArray());
                return default;
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
