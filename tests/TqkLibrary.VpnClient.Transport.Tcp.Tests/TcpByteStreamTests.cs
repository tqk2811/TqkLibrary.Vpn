using System.Net;
using System.Net.Sockets;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Transport.Tcp;
using Xunit;

namespace TqkLibrary.VpnClient.Transport.Tcp.Tests
{
    /// <summary>
    /// Offline coverage for the shared plain-TCP byte stream (<see cref="TcpByteStream"/>, roadmap F.1). Each round-trip
    /// runs against a loopback <see cref="TcpListener"/> (no external network — NOT marked Integration), exercising both
    /// constructors (pre-resolved endpoint and resolve-by-host) plus the not-connected guards.
    /// </summary>
    public class TcpByteStreamTests
    {
        [Fact]
        public async Task RoundTrips_OverLoopback_PreResolvedEndpoint()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = EchoOnceAsync(listener, 4);

                using var client = new TcpByteStream(new IPEndPoint(IPAddress.Loopback, port));
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                await client.WriteAsync(new byte[] { 9, 8, 7, 6 }, cts.Token);
                byte[] echo = await ReadExactlyAsync(client, 4, cts.Token);

                Assert.Equal(new byte[] { 9, 8, 7, 6 }, echo);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public async Task RoundTrips_OverLoopback_ResolvedHost()
        {
            // The host ctor goes through DnsHostResolver (a literal "127.0.0.1" resolves to itself), proving the
            // resolve path + AddressFamilyPreference plumbing the TLS layer relies on.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = EchoOnceAsync(listener, 3);

                using var client = new TcpByteStream("127.0.0.1", port, AddressFamilyPreference.IPv4);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await client.ConnectAsync(cts.Token);

                await client.WriteAsync(new byte[] { 1, 2, 3 }, cts.Token);
                byte[] echo = await ReadExactlyAsync(client, 3, cts.Token);

                Assert.Equal(new byte[] { 1, 2, 3 }, echo);
                Assert.Equal("127.0.0.1", client.Host);
                await server;
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public void Stream_BeforeConnect_Throws()
        {
            using var s = new TcpByteStream(new IPEndPoint(IPAddress.Loopback, 1));
            Assert.Throws<InvalidOperationException>(() => s.Stream);
        }

        [Fact]
        public async Task ReadAsync_BeforeConnect_Throws()
        {
            using var s = new TcpByteStream(new IPEndPoint(IPAddress.Loopback, 1));
            await Assert.ThrowsAsync<InvalidOperationException>(() => s.ReadAsync(new byte[4]).AsTask());
        }

        [Fact]
        public void Dispose_BeforeConnect_DoesNotThrow()
        {
            var s = new TcpByteStream(new IPEndPoint(IPAddress.Loopback, 1));
            s.Dispose();   // idempotent / safe with no socket yet
            s.Dispose();
        }

        // Accepts one client, echoes back the first <paramref name="count"/> bytes, then closes.
        static async Task EchoOnceAsync(TcpListener listener, int count)
        {
            using TcpClient server = await listener.AcceptTcpClientAsync();
            NetworkStream ns = server.GetStream();
            byte[] buf = new byte[count];
            int read = 0;
            while (read < count)
            {
                int r = await ns.ReadAsync(buf, read, count - read);
                if (r == 0) break;
                read += r;
            }
            await ns.WriteAsync(buf, 0, read);
        }

        static async Task<byte[]> ReadExactlyAsync(TcpByteStream client, int count, CancellationToken ct)
        {
            byte[] buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int r = await client.ReadAsync(buffer.AsMemory(read), ct);
                if (r == 0) break;
                read += r;
            }
            return buffer;
        }
    }
}
