using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.OpenVpn.Transport;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests the V2.h UDP transport: <see cref="OpenVpnUdpTransport"/> puts <see cref="IOpenVpnTransport"/> on a
    /// datagram pipe with no framing — one datagram in equals one packet out, boundaries preserved, and a zero-length
    /// datagram does not stop the receive loop (UDP has no end-of-stream).
    /// </summary>
    public class OpenVpnUdpTransportTests
    {
        [Fact]
        public async Task SendAsync_WritesOneDatagramPerPacket()
        {
            var pipe = new LoopbackDatagram();
            var transport = new OpenVpnUdpTransport(pipe);

            await transport.SendAsync(new byte[] { 1, 2, 3 });
            await transport.SendAsync(new byte[] { 9 });

            Assert.Equal(2, pipe.Sent.Count);
            Assert.Equal(new byte[] { 1, 2, 3 }, pipe.Sent[0]);
            Assert.Equal(new byte[] { 9 }, pipe.Sent[1]);
        }

        [Fact]
        public async Task ReceiveLoop_RaisesOneEventPerDatagram_WithBoundariesPreserved()
        {
            var pipe = new LoopbackDatagram();
            var transport = new OpenVpnUdpTransport(pipe);
            var received = new List<byte[]>();
            transport.DatagramReceived += m => received.Add(m.ToArray());

            // Two distinct datagrams must surface as two packets — never coalesced (the UDP boundary is the frame).
            pipe.Deliver(new byte[] { 0x10, 0x11 });
            pipe.Deliver(new byte[] { 0x20 });
            pipe.Complete();

            await transport.RunReceiveLoopAsync(pipe.Cancellation);

            Assert.Equal(2, received.Count);
            Assert.Equal(new byte[] { 0x10, 0x11 }, received[0]);
            Assert.Equal(new byte[] { 0x20 }, received[1]);
        }

        [Fact]
        public async Task ReceiveLoop_IgnoresZeroLengthDatagram_AndKeepsListening()
        {
            var pipe = new LoopbackDatagram();
            var transport = new OpenVpnUdpTransport(pipe);
            var received = new List<byte[]>();
            transport.DatagramReceived += m => received.Add(m.ToArray());

            pipe.Deliver(System.Array.Empty<byte>()); // 0-length: must NOT end the loop (unlike a TCP read of 0)
            pipe.Deliver(new byte[] { 0x42 });
            pipe.Complete();

            await transport.RunReceiveLoopAsync(pipe.Cancellation);

            Assert.Single(received);
            Assert.Equal(new byte[] { 0x42 }, received[0]);
        }

        /// <summary>An in-memory <see cref="IDatagramTransport"/>: records sends; serves queued datagrams to the loop, then cancels.</summary>
        sealed class LoopbackDatagram : IDatagramTransport
        {
            readonly Queue<byte[]> _inbound = new();
            readonly CancellationTokenSource _cts = new();

            public List<byte[]> Sent { get; } = new();
            public CancellationToken Cancellation => _cts.Token;

            public void Deliver(byte[] datagram) => _inbound.Enqueue(datagram);
            public void Complete() { } // queued datagrams drain, then ReceiveAsync cancels the loop

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                Sent.Add(datagram.ToArray());
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_inbound.Count == 0) { _cts.Cancel(); cancellationToken.ThrowIfCancellationRequested(); }
                byte[] datagram = _inbound.Dequeue();
                datagram.CopyTo(buffer);
                return new ValueTask<int>(datagram.Length);
            }

            public ValueTask DisposeAsync() => default;
        }
    }
}
