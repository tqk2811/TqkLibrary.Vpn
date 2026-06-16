using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenVpn.Transport;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.g TCP transport: the 16-bit length framing codec (encode + reassembly across arbitrary read
    /// boundaries) and the <see cref="OpenVpnTcpTransport"/> adapter that puts <see cref="IOpenVpnTransport"/> on a
    /// reliable byte stream.
    /// </summary>
    public class OpenVpnTcpTransportTests
    {
        [Fact]
        public void Encode_PrependsBigEndianLength()
        {
            byte[] framed = OpenVpnTcpFraming.Encode(new byte[] { 0xAA, 0xBB, 0xCC });
            Assert.Equal(new byte[] { 0x00, 0x03, 0xAA, 0xBB, 0xCC }, framed);
        }

        [Fact]
        public void Encode_RejectsEmptyAndOversize()
        {
            Assert.Throws<ArgumentException>(() => OpenVpnTcpFraming.Encode(Array.Empty<byte>()));
            Assert.Throws<ArgumentOutOfRangeException>(() => OpenVpnTcpFraming.Encode(new byte[OpenVpnTcpFraming.MaxPacketLength + 1]));
        }

        [Fact]
        public void Decoder_ReassemblesPacketSplitAcrossReads()
        {
            byte[] framed = OpenVpnTcpFraming.Encode(new byte[] { 1, 2, 3, 4, 5 });
            var f = new OpenVpnTcpFraming();

            // Feed the frame one byte at a time: nothing emerges until the last byte arrives.
            for (int i = 0; i < framed.Length - 1; i++)
            {
                f.Append(framed.AsSpan(i, 1));
                Assert.False(f.TryReadPacket(out _));
            }
            f.Append(framed.AsSpan(framed.Length - 1, 1));
            Assert.True(f.TryReadPacket(out byte[] packet));
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, packet);
            Assert.False(f.TryReadPacket(out _));
        }

        [Fact]
        public void Decoder_SplitsTwoPacketsCoalescedInOneChunk()
        {
            var f = new OpenVpnTcpFraming();
            byte[] a = OpenVpnTcpFraming.Encode(new byte[] { 0x10 });
            byte[] b = OpenVpnTcpFraming.Encode(new byte[] { 0x20, 0x21 });
            byte[] both = new byte[a.Length + b.Length];
            a.CopyTo(both, 0);
            b.CopyTo(both, a.Length);

            f.Append(both);
            Assert.True(f.TryReadPacket(out byte[] p1));
            Assert.Equal(new byte[] { 0x10 }, p1);
            Assert.True(f.TryReadPacket(out byte[] p2));
            Assert.Equal(new byte[] { 0x20, 0x21 }, p2);
            Assert.False(f.TryReadPacket(out _));
        }

        [Fact]
        public async Task Transport_FramesOnSend_AndReassemblesOnReceive()
        {
            // A loopback stream that hands bytes back in tiny 1-byte reads to stress reassembly.
            var loop = new LoopbackByteStream(maxReadChunk: 1);
            var transport = new OpenVpnTcpTransport(loop, readBufferSize: 64);
            var received = new List<byte[]>();
            transport.DatagramReceived += m => received.Add(m.ToArray());

            // Queue both frames (and close) before pumping, so the read loop drains then sees end-of-stream — no race.
            await transport.SendAsync(new byte[] { 1, 2, 3 });
            await transport.SendAsync(new byte[] { 9 });
            await transport.RunReceiveLoopAsync();

            Assert.Equal(2, received.Count);
            Assert.Equal(new byte[] { 1, 2, 3 }, received[0]);
            Assert.Equal(new byte[] { 9 }, received[1]);
        }

        /// <summary>In-memory <see cref="IByteStreamTransport"/>: writes are queued and served back to reads (loopback).</summary>
        sealed class LoopbackByteStream : IByteStreamTransport
        {
            readonly object _sync = new();
            readonly Queue<byte> _queue = new();
            readonly int _maxReadChunk;

            public LoopbackByteStream(int maxReadChunk) => _maxReadChunk = maxReadChunk;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            {
                lock (_sync)
                    foreach (byte b in buffer.Span) _queue.Enqueue(b);
                return default;
            }

            public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                lock (_sync)
                {
                    if (_queue.Count == 0) return new ValueTask<int>(0); // drained ⇒ end-of-stream (writes are completed)
                    int n = Math.Min(Math.Min(_maxReadChunk, buffer.Length), _queue.Count);
                    for (int i = 0; i < n; i++) buffer.Span[i] = _queue.Dequeue();
                    return new ValueTask<int>(n);
                }
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
